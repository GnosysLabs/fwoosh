//! Encrypted local history store (redb — pure-Rust embedded DB).
//!
//! Each clip's **text** is encrypted at rest with XChaCha20-Poly1305 using the
//! history DB key held in the OS keychain (see `keychain.rs`). This key is
//! deliberately SEPARATE from the device keypairs: a leaked group/device secret
//! does not by itself expose stored history.
//!
//! Metadata (sender id, timestamp) is stored alongside the ciphertext so the
//! list renders without decryption; only the payload (text) is encrypted.
//!
//! Nonce = random 192-bit per row (XChaCha20 safety margin). Each row uses its
//! own random nonce under a stable key, so accidental reuse is astronomically
//! unlikely (2^96 birthday bound).
//!
//! Why redb over SQLite: redb is pure Rust (no C compile), which lets the
//! project build on machines where the MSVC C++ headers aren't installed. The
//! abstraction is the same (encrypted blobs keyed by id).

use crate::crypto::Ed25519PubKey;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;
use std::sync::Mutex;

/// Max clips retained in history (oldest evicted).
const MAX_HISTORY: usize = 500;

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("clips");

#[derive(Debug)]
pub enum StoreError {
    Db(redb::Error),
    Transaction(redb::TransactionError),
    Commit(redb::CommitError),
    Table(redb::TableError),
    Database(redb::DatabaseError),
    Encrypt,
    Decrypt,
    BadRow(&'static str),
    Storage(redb::StorageError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "db: {e}"),
            Self::Transaction(e) => write!(f, "tx: {e}"),
            Self::Commit(e) => write!(f, "commit: {e}"),
            Self::Table(e) => write!(f, "table: {e}"),
            Self::Database(e) => write!(f, "database: {e}"),
            Self::Encrypt => write!(f, "encryption failed"),
            Self::Decrypt => write!(f, "decryption failed"),
            Self::BadRow(m) => write!(f, "bad row: {m}"),
            Self::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self { Self::Db(e) }
}
impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self { Self::Transaction(e) }
}
impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self { Self::Commit(e) }
}
impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self { Self::Table(e) }
}
impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self { Self::Database(e) }
}
impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self { Self::Storage(e) }
}

/// A decrypted history row.
#[derive(Clone, Debug)]
pub struct HistoryClip {
    pub id: u64,
    pub sender_id: Ed25519PubKey,
    pub ts: u64,
    pub text: String,
}

/// Thread-safe handle around the redb database + the encryption key.
pub struct HistoryStore {
    db: Mutex<Database>,
    cipher: XChaCha20Poly1305,
    next_id: Mutex<u64>,
}

impl HistoryStore {
    /// Open (creating if needed) the history DB at `path`, encrypted with `db_key`.
    pub fn open(path: &Path, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        {
            let mut tx = db.begin_write()?;
            // Use low durability for the schema-creation tx (cheap, fast).
            let _ = tx.set_durability(Durability::None);
            tx.open_table(TABLE)?;
            tx.commit()?;
        }
        // Seed the next id from the max existing key + 1.
        let start = {
            let rx = db.begin_read()?;
            let table = rx.open_table(TABLE)?;
            let last_key: Option<u64> = table.last()?.map(|(k, _)| k.value());
            last_key.map(|k| k + 1).unwrap_or(1)
        };
        Ok(Self {
            db: Mutex::new(db),
            cipher: XChaCha20Poly1305::new(db_key.into()),
            next_id: Mutex::new(start),
        })
    }

    /// Encrypt + insert a clip. Returns its row id.
    pub fn insert(
        &self,
        sender_id: &Ed25519PubKey,
        ts: u64,
        text: &str,
    ) -> Result<u64, StoreError> {
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let ct = self
            .cipher
            .encrypt(&XNonce::from(nonce), text.as_bytes())
            .map_err(|_| StoreError::Encrypt)?;

        // Row layout: sender_id[32] || ts[u64 BE] || nonce[24] || ciphertext
        let mut row = Vec::with_capacity(32 + 8 + 24 + ct.len());
        row.extend_from_slice(&sender_id.0);
        row.extend_from_slice(&ts.to_be_bytes());
        row.extend_from_slice(&nonce);
        row.extend_from_slice(&ct);

        let id = {
            let mut g = self.next_id.lock().unwrap();
            let id = *g;
            *g += 1;
            id
        };

        let db = self.db.lock().unwrap();
        {
            let mut tx = db.begin_write()?;
            // Durability::None avoids an fsync per clip; local clipboard history
            // is also re-deliverable from peers, so this trade is acceptable.
            let _ = tx.set_durability(Durability::None);
            {
                let mut table = tx.open_table(TABLE)?;
                table.insert(id, row.as_slice())?;
            }
            tx.commit()?;
        }
        drop(db);

        self.evict_if_needed()?;
        Ok(id)
    }

    fn evict_if_needed(&self) -> Result<(), StoreError> {
        let db = self.db.lock().unwrap();
        let to_drop: Vec<u64> = {
            let rx = db.begin_read()?;
            let table = rx.open_table(TABLE)?;
            let count = table.len()?;
            if count > MAX_HISTORY as u64 {
                table
                    .iter()?
                    .take((count - MAX_HISTORY as u64) as usize)
                    .map(|r| r.map(|(k, _)| k.value()).unwrap_or(0))
                    .collect()
            } else {
                Vec::new()
            }
        };
        if !to_drop.is_empty() {
            let mut tx = db.begin_write()?;
            let _ = tx.set_durability(Durability::None);
            {
                let mut table = tx.open_table(TABLE)?;
                for id in to_drop {
                    let _ = table.remove(id);
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    /// Return the most recent `limit` clips, decrypted.
    pub fn recent(&self, limit: usize) -> Result<Vec<HistoryClip>, StoreError> {
        let db = self.db.lock().unwrap();
        let rx = db.begin_read()?;
        let table = rx.open_table(TABLE)?;
        let mut out = Vec::new();
        for r in table.iter()?.rev().take(limit) {
            let (k, v) = r?;
            let row = v.value();
            if row.len() < 32 + 8 + 24 {
                return Err(StoreError::BadRow("row too short"));
            }
            let mut sn = [0u8; 32];
            sn.copy_from_slice(&row[..32]);
            let ts = u64::from_be_bytes(row[32..40].try_into().unwrap());
            let mut nc = [0u8; 24];
            nc.copy_from_slice(&row[40..64]);
            let ct = &row[64..];
            let pt = self
                .cipher
                .decrypt(&XNonce::from(nc), ct)
                .map_err(|_| StoreError::Decrypt)?;
            let text = String::from_utf8(pt).map_err(|_| StoreError::BadRow("non-utf8 text"))?;
            out.push(HistoryClip { id: k.value(), sender_id: Ed25519PubKey(sn), ts, text });
        }
        Ok(out)
    }

    /// Delete a single clip by id.
    pub fn delete(&self, id: u64) -> Result<(), StoreError> {
        let db = self.db.lock().unwrap();
        let mut tx = db.begin_write()?;
        let _ = tx.set_durability(Durability::None);
        {
            let mut table = tx.open_table(TABLE)?;
            table.remove(id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Full-text search over decrypted clips (decrypts then filters; fine for
    /// the small caps we keep).
    pub fn search(&self, needle: &str, limit: usize) -> Result<Vec<HistoryClip>, StoreError> {
        let all = self.recent(MAX_HISTORY)?;
        let n = needle.to_lowercase();
        Ok(all
            .into_iter()
            .filter(|c| c.text.to_lowercase().contains(&n))
            .take(limit)
            .collect())
    }

    /// Total stored clip count.
    pub fn count(&self) -> Result<u64, StoreError> {
        let db = self.db.lock().unwrap();
        let rx = db.begin_read()?;
        let table = rx.open_table(TABLE)?;
        Ok(table.len()?)
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
        let store = HistoryStore::open(&dir.path().join("h.redb"), &test_key()).unwrap();
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
        let store = HistoryStore::open(&dir.path().join("h.redb"), &test_key()).unwrap();
        let sender = Ed25519PubKey([0xCD; 32]);
        let id = store.insert(&sender, 50, "bye").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.delete(id).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn search_finds_matches() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("h.redb"), &test_key()).unwrap();
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
        let store = HistoryStore::open(&dir.path().join("h.redb"), &test_key()).unwrap();
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
        let path = dir.path().join("h.redb");
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
}
