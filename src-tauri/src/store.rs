//! Encrypted local history store (SQLite via rusqlite).
//!
//! Each clip's **text** is encrypted at rest with XChaCha20-Poly1305 using the
//! history DB key held in the OS keychain (see `keychain.rs`). This key is
//! deliberately SEPARATE from the device keypairs: a leaked group/device secret
//! does not by itself expose stored history.
//!
//! Metadata (sender id, timestamp) is stored in plaintext so the list renders
//! without decryption; only the payload (text) is encrypted.
//!
//! Nonce = random 192-bit per row (XChaCha20 safety margin). Each row uses its
//! own random nonce under a stable key, so accidental reuse is astronomically
//! unlikely (2^96 birthday bound).

use crate::crypto::Ed25519PubKey;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

/// Max clips retained in history (oldest evicted).
const MAX_HISTORY: i64 = 500;
/// Max successfully-opened relay message IDs retained for replay rejection.
const MAX_SEEN_MESSAGES: i64 = 4096;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Encrypt,
    Decrypt,
    BadRow(&'static str),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::Encrypt => write!(f, "encryption failed"),
            Self::Decrypt => write!(f, "decryption failed"),
            Self::BadRow(m) => write!(f, "bad row: {m}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// A decrypted history row.
#[derive(Clone, Debug)]
pub struct HistoryClip {
    pub id: i64,
    pub msg_id: Option<[u8; 16]>,
    pub sender_id: Ed25519PubKey,
    pub ts: u64,
    pub text: String,
}

/// Thread-safe handle around the SQLite connection + the encryption key.
pub struct HistoryStore {
    conn: Mutex<Connection>,
    cipher: XChaCha20Poly1305,
}

impl HistoryStore {
    /// Open (creating if needed) the history DB at `path`, encrypted with `db_key`.
    pub fn open(path: &Path, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // WAL mode for better concurrency + crash durability.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS clips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id      BLOB UNIQUE,
                group_id    TEXT NOT NULL DEFAULT '',
                sender_id   BLOB NOT NULL,
                ts          INTEGER NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_clips_ts ON clips(ts DESC);

            CREATE TABLE IF NOT EXISTS seen_messages (
                msg_id      BLOB PRIMARY KEY,
                ts          INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_seen_messages_ts
                ON seen_messages(ts DESC);",
        )?;
        Self::ensure_clip_msg_id_column(&conn)?;
        Self::ensure_clip_group_id_column(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            cipher: XChaCha20Poly1305::new(db_key.into()),
        })
    }

    fn ensure_clip_msg_id_column(conn: &Connection) -> Result<(), StoreError> {
        let mut stmt = conn.prepare("PRAGMA table_info(clips)")?;
        let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut has_msg_id = false;
        for col in cols {
            if col? == "msg_id" {
                has_msg_id = true;
                break;
            }
        }
        if !has_msg_id {
            conn.execute("ALTER TABLE clips ADD COLUMN msg_id BLOB", [])?;
        }
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_clips_msg_id ON clips(msg_id)",
            [],
        )?;
        Ok(())
    }

    fn ensure_clip_group_id_column(conn: &Connection) -> Result<(), StoreError> {
        let mut stmt = conn.prepare("PRAGMA table_info(clips)")?;
        let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut has_group_id = false;
        for col in cols {
            if col? == "group_id" {
                has_group_id = true;
                break;
            }
        }
        if !has_group_id {
            conn.execute(
                "ALTER TABLE clips ADD COLUMN group_id TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_clips_group_ts ON clips(group_id, ts DESC)",
            [],
        )?;
        Ok(())
    }

    /// Assign rows from the legacy single-group schema to the migrated group.
    pub fn assign_legacy_group(&self, group_id: &str) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "UPDATE clips SET group_id = ?1 WHERE group_id = ''",
            params![group_id],
        )?)
    }

    pub fn insert_with_msg_id_in_group(
        &self,
        group_id: &str,
        sender_id: &Ed25519PubKey,
        ts: u64,
        text: &str,
        msg_id: Option<&[u8; 16]>,
    ) -> Result<i64, StoreError> {
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let ct = self
            .cipher
            .encrypt(&XNonce::from(nonce), text.as_bytes())
            .map_err(|_| StoreError::Encrypt)?;

        let conn = self.conn.lock().unwrap();
        let msg_id_blob = msg_id.map(|m| m.to_vec());
        conn.execute(
            "INSERT INTO clips (msg_id, group_id, sender_id, ts, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg_id_blob,
                group_id,
                &sender_id.0[..],
                ts as i64,
                &nonce[..],
                &ct[..]
            ],
        )?;
        let id = conn.last_insert_rowid();

        // Evict oldest beyond the cap.
        conn.execute(
            "DELETE FROM clips WHERE id NOT IN (
                SELECT id FROM clips ORDER BY ts DESC, id DESC LIMIT ?1
             )",
            params![MAX_HISTORY],
        )?;
        Ok(id)
    }

    pub fn recent_for_group(
        &self,
        group_id: &str,
        limit: i64,
    ) -> Result<Vec<HistoryClip>, StoreError> {
        self.recent_scoped(group_id, limit)
    }

    fn recent_scoped(&self, group_id: &str, limit: i64) -> Result<Vec<HistoryClip>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, msg_id, sender_id, ts, nonce, ciphertext FROM clips
             WHERE group_id = ?1
             ORDER BY ts DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![group_id, limit], |row| {
            let id: i64 = row.get(0)?;
            let msg_id: Option<Vec<u8>> = row.get(1)?;
            let sender: Vec<u8> = row.get(2)?;
            let ts: i64 = row.get(3)?;
            let nonce: Vec<u8> = row.get(4)?;
            let ct: Vec<u8> = row.get(5)?;
            Ok((id, msg_id, sender, ts, nonce, ct))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id, msg_id, sender, ts, nonce, ct) = r?;
            if sender.len() != 32 || nonce.len() != 24 {
                return Err(StoreError::BadRow("sender/nonce length"));
            }
            let msg_id = msg_id
                .map(|blob| {
                    if blob.len() != 16 {
                        return Err(StoreError::BadRow("msg_id length"));
                    }
                    let mut out = [0u8; 16];
                    out.copy_from_slice(&blob);
                    Ok(out)
                })
                .transpose()?;
            let mut sn = [0u8; 32];
            sn.copy_from_slice(&sender);
            let mut nc = [0u8; 24];
            nc.copy_from_slice(&nonce);
            let pt = self
                .cipher
                .decrypt(&XNonce::from(nc), &ct[..])
                .map_err(|_| StoreError::Decrypt)?;
            let text = String::from_utf8(pt).map_err(|_| StoreError::BadRow("non-utf8 text"))?;
            out.push(HistoryClip {
                id,
                msg_id,
                sender_id: Ed25519PubKey(sn),
                ts: ts as u64,
                text,
            });
        }
        Ok(out)
    }

    /// Delete a single clip by id.
    pub fn delete(&self, id: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM clips WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn all_msg_ids_for_group(&self, group_id: &str) -> Result<Vec<[u8; 16]>, StoreError> {
        self.all_msg_ids_scoped(group_id)
    }

    fn all_msg_ids_scoped(&self, group_id: &str) -> Result<Vec<[u8; 16]>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT msg_id FROM clips
             WHERE msg_id IS NOT NULL AND group_id = ?1",
        )?;
        let rows = stmt.query_map(params![group_id], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let blob = row?;
            if blob.len() != 16 {
                return Err(StoreError::BadRow("msg_id length"));
            }
            let mut msg_id = [0u8; 16];
            msg_id.copy_from_slice(&blob);
            out.push(msg_id);
        }
        Ok(out)
    }

    pub fn delete_all_for_group(&self, group_id: &str) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM clips WHERE group_id = ?1", params![group_id])?)
    }

    /// Return the relay message id for a local history row, if it has one.
    pub fn msg_id_for_clip(&self, id: i64) -> Result<Option<[u8; 16]>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let raw: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT msg_id FROM clips WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(Some(blob)) = raw else {
            return Ok(None);
        };
        if blob.len() != 16 {
            return Err(StoreError::BadRow("msg_id length"));
        }
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&blob);
        Ok(Some(msg_id))
    }

    pub fn group_id_for_clip(&self, id: i64) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT group_id FROM clips WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Delete a clip by relay message id. Returns how many local rows changed.
    pub fn delete_by_msg_id(&self, msg_id: &[u8; 16]) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM clips WHERE msg_id = ?1", params![&msg_id[..]])?;
        Ok(changed)
    }

    /// Full-text search over decrypted clips (decrypts then filters; fine for
    /// the small caps we keep). A future version can use SQLite FTS5 on an
    /// encrypted index, but correctness-first here.
    pub fn search_for_group(
        &self,
        group_id: &str,
        needle: &str,
        limit: i64,
    ) -> Result<Vec<HistoryClip>, StoreError> {
        self.search_scoped(group_id, needle, limit)
    }

    fn search_scoped(
        &self,
        group_id: &str,
        needle: &str,
        limit: i64,
    ) -> Result<Vec<HistoryClip>, StoreError> {
        let all = self.recent_scoped(group_id, MAX_HISTORY)?;
        let n = needle.to_lowercase();
        Ok(all
            .into_iter()
            .filter(|c| c.text.to_lowercase().contains(&n))
            .take(limit as usize)
            .collect())
    }

    /// Total stored clip count.
    pub fn count(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row("SELECT COUNT(*) FROM clips", [], |row| row.get(0))
            .optional()?
            .unwrap_or(0))
    }

    /// Return true if this relay message ID was already opened successfully.
    pub fn has_seen_message(&self, msg_id: &[u8; 16]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM seen_messages WHERE msg_id = ?1)",
            params![&msg_id[..]],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    /// Remember a successfully-opened relay message ID for replay rejection.
    pub fn mark_seen_message(&self, msg_id: &[u8; 16], ts: u64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO seen_messages (msg_id, ts) VALUES (?1, ?2)",
            params![&msg_id[..], ts as i64],
        )?;
        conn.execute(
            "DELETE FROM seen_messages WHERE msg_id NOT IN (
                SELECT msg_id FROM seen_messages ORDER BY ts DESC LIMIT ?1
             )",
            params![MAX_SEEN_MESSAGES],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_GROUP: &str = "test";

    fn test_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn insert_and_recent() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xAB; 32]);
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 100, "first clip", None)
            .unwrap();
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 200, "second clip", None)
            .unwrap();
        let clips = store.recent_for_group(TEST_GROUP, 10).unwrap();
        assert_eq!(clips.len(), 2);
        assert_eq!(clips[0].text, "second clip");
        assert_eq!(clips[1].text, "first clip");
    }

    #[test]
    fn delete_removes_clip() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xCD; 32]);
        let id = store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 50, "bye", None)
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.delete(id).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn msg_id_roundtrip_and_delete() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xEF; 32]);
        let msg_id = [0x42; 16];
        let id = store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 70, "shared delete", Some(&msg_id))
            .unwrap();

        assert_eq!(store.msg_id_for_clip(id).unwrap(), Some(msg_id));
        let clips = store.recent_for_group(TEST_GROUP, 10).unwrap();
        assert_eq!(clips[0].msg_id, Some(msg_id));
        assert_eq!(store.delete_by_msg_id(&msg_id).unwrap(), 1);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn all_msg_ids_and_delete_all() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xBC; 32]);
        let msg_a = [0x01; 16];
        let msg_b = [0x02; 16];
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 1, "one", Some(&msg_a))
            .unwrap();
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 2, "local", None)
            .unwrap();
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 3, "two", Some(&msg_b))
            .unwrap();

        let ids = store.all_msg_ids_for_group(TEST_GROUP).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&msg_a));
        assert!(ids.contains(&msg_b));
        assert_eq!(store.delete_all_for_group(TEST_GROUP).unwrap(), 3);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn opening_legacy_schema_adds_msg_id_column() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("h.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE clips (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id   BLOB NOT NULL,
                    ts          INTEGER NOT NULL,
                    nonce       BLOB NOT NULL,
                    ciphertext  BLOB NOT NULL
                );
                CREATE TABLE seen_messages (
                    msg_id      BLOB PRIMARY KEY,
                    ts          INTEGER NOT NULL
                );",
            )
            .unwrap();
        }

        let store = HistoryStore::open(&path, &test_key()).unwrap();
        let sender = Ed25519PubKey([0xAA; 32]);
        let msg_id = [0x99; 16];
        let id = store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 1, "after migration", Some(&msg_id))
            .unwrap();
        assert_eq!(store.msg_id_for_clip(id).unwrap(), Some(msg_id));
    }

    #[test]
    fn search_finds_matches() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x11; 32]);
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 1, "hello world", None)
            .unwrap();
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 2, "another CLIP here", None)
            .unwrap();
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 3, "unrelated", None)
            .unwrap();
        let hits = store.search_for_group(TEST_GROUP, "clip", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "another CLIP here");
    }

    #[test]
    fn sync_group_history_is_isolated() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x22; 32]);
        let work_msg = [0x31; 16];
        let friends_msg = [0x32; 16];
        store
            .insert_with_msg_id_in_group("work", &sender, 1, "quarterly plan", Some(&work_msg))
            .unwrap();
        store
            .insert_with_msg_id_in_group("friends", &sender, 2, "weekend plan", Some(&friends_msg))
            .unwrap();

        let work = store.recent_for_group("work", 10).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].text, "quarterly plan");
        assert_eq!(store.all_msg_ids_for_group("work").unwrap(), vec![work_msg]);

        let friends = store.search_for_group("friends", "weekend", 10).unwrap();
        assert_eq!(friends.len(), 1);
        assert_eq!(store.delete_all_for_group("work").unwrap(), 1);
        assert!(store.recent_for_group("work", 10).unwrap().is_empty());
        assert_eq!(store.recent_for_group("friends", 10).unwrap().len(), 1);
    }

    #[test]
    fn large_text_stored_and_recovered() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x22; 32]);
        let big = "Z".repeat(50_000);
        store
            .insert_with_msg_id_in_group(TEST_GROUP, &sender, 1, &big, None)
            .unwrap();
        let clips = store.recent_for_group(TEST_GROUP, 1).unwrap();
        assert_eq!(clips[0].text.len(), 50_000);
        assert_eq!(clips[0].text, big);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("h.db");
        let sender = Ed25519PubKey([0x44; 32]);
        {
            let store = HistoryStore::open(&path, &test_key()).unwrap();
            store
                .insert_with_msg_id_in_group(TEST_GROUP, &sender, 7, "persistent", None)
                .unwrap();
        }
        let store = HistoryStore::open(&path, &test_key()).unwrap();
        let clips = store.recent_for_group(TEST_GROUP, 10).unwrap();
        assert_eq!(clips.len(), 1);
        assert_eq!(clips[0].text, "persistent");
    }

    #[test]
    fn eviction_keeps_cap() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x33; 32]);
        for i in 0..(MAX_HISTORY + 50) {
            store
                .insert_with_msg_id_in_group(
                    TEST_GROUP,
                    &sender,
                    i as u64,
                    &format!("clip {i}"),
                    None,
                )
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), MAX_HISTORY);
        let top = store.recent_for_group(TEST_GROUP, 1).unwrap();
        assert_eq!(top[0].text, format!("clip {}", MAX_HISTORY + 49));
    }

    #[test]
    fn seen_messages_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("h.db");
        let msg_id = [0xAA; 16];
        {
            let store = HistoryStore::open(&path, &test_key()).unwrap();
            assert!(!store.has_seen_message(&msg_id).unwrap());
            store.mark_seen_message(&msg_id, 123).unwrap();
            assert!(store.has_seen_message(&msg_id).unwrap());
        }
        let store = HistoryStore::open(&path, &test_key()).unwrap();
        assert!(store.has_seen_message(&msg_id).unwrap());
    }
}
