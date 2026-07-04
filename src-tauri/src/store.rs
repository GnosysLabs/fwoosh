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
    fn from(e: rusqlite::Error) -> Self { Self::Sqlite(e) }
}

/// A decrypted history row.
#[derive(Clone, Debug)]
pub struct HistoryClip {
    pub id: i64,
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
                sender_id   BLOB NOT NULL,
                ts          INTEGER NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_clips_ts ON clips(ts DESC);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            cipher: XChaCha20Poly1305::new(db_key.into()),
        })
    }

    /// Encrypt + insert a clip. Returns its row id.
    pub fn insert(
        &self,
        sender_id: &Ed25519PubKey,
        ts: u64,
        text: &str,
    ) -> Result<i64, StoreError> {
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let ct = self
            .cipher
            .encrypt(&XNonce::from(nonce), text.as_bytes())
            .map_err(|_| StoreError::Encrypt)?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO clips (sender_id, ts, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4)",
            params![&sender_id.0[..], ts as i64, &nonce[..], &ct[..]],
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

    /// Return the most recent `limit` clips, decrypted.
    pub fn recent(&self, limit: i64) -> Result<Vec<HistoryClip>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sender_id, ts, nonce, ciphertext FROM clips
             ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let id: i64 = row.get(0)?;
            let sender: Vec<u8> = row.get(1)?;
            let ts: i64 = row.get(2)?;
            let nonce: Vec<u8> = row.get(3)?;
            let ct: Vec<u8> = row.get(4)?;
            Ok((id, sender, ts, nonce, ct))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id, sender, ts, nonce, ct) = r?;
            if sender.len() != 32 || nonce.len() != 24 {
                return Err(StoreError::BadRow("sender/nonce length"));
            }
            let mut sn = [0u8; 32];
            sn.copy_from_slice(&sender);
            let mut nc = [0u8; 24];
            nc.copy_from_slice(&nonce);
            let pt = self
                .cipher
                .decrypt(&XNonce::from(nc), &ct[..])
                .map_err(|_| StoreError::Decrypt)?;
            let text = String::from_utf8(pt).map_err(|_| StoreError::BadRow("non-utf8 text"))?;
            out.push(HistoryClip { id, sender_id: Ed25519PubKey(sn), ts: ts as u64, text });
        }
        Ok(out)
    }

    /// Delete a single clip by id.
    pub fn delete(&self, id: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM clips WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Full-text search over decrypted clips (decrypts then filters; fine for
    /// the small caps we keep). A future version can use SQLite FTS5 on an
    /// encrypted index, but correctness-first here.
    pub fn search(&self, needle: &str, limit: i64) -> Result<Vec<HistoryClip>, StoreError> {
        let all = self.recent(MAX_HISTORY)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        store.insert(&sender, 100, "first clip").unwrap();
        store.insert(&sender, 200, "second clip").unwrap();
        let clips = store.recent(10).unwrap();
        assert_eq!(clips.len(), 2);
        assert_eq!(clips[0].text, "second clip");
        assert_eq!(clips[1].text, "first clip");
    }

    #[test]
    fn delete_removes_clip() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xCD; 32]);
        let id = store.insert(&sender, 50, "bye").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.delete(id).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn search_finds_matches() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x11; 32]);
        store.insert(&sender, 1, "hello world").unwrap();
        store.insert(&sender, 2, "another CLIP here").unwrap();
        store.insert(&sender, 3, "unrelated").unwrap();
        let hits = store.search("clip", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "another CLIP here");
    }

    #[test]
    fn large_text_stored_and_recovered() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x22; 32]);
        let big = "Z".repeat(50_000);
        store.insert(&sender, 1, &big).unwrap();
        let clips = store.recent(1).unwrap();
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
            store.insert(&sender, 7, "persistent").unwrap();
        }
        let store = HistoryStore::open(&path, &test_key()).unwrap();
        let clips = store.recent(10).unwrap();
        assert_eq!(clips.len(), 1);
        assert_eq!(clips[0].text, "persistent");
    }

    #[test]
    fn eviction_keeps_cap() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.db"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0x33; 32]);
        for i in 0..(MAX_HISTORY + 50) {
            store.insert(&sender, i as u64, &format!("clip {i}")).unwrap();
        }
        assert_eq!(store.count().unwrap(), MAX_HISTORY);
        let top = store.recent(1).unwrap();
        assert_eq!(top[0].text, format!("clip {}", MAX_HISTORY + 49));
    }
}
