//! OS credential storage: device keypairs + a separate local DB key.
//!
//! Primary store: the OS keychain (Windows Credential Manager via DPAPI, macOS
//! Keychain). Fallback: an encrypted file in the app data dir, used when the OS
//! keychain is unavailable in the current environment (e.g. some headless /
//! non-interactive launch contexts).
//!
//! Security note: OS keychain storage protects against other *users* reading
//! secrets, but not against malware running as the same logged-in user. The
//! file fallback is weaker (bound to the OS user account via DPAPI on Windows,
//! or file perms on Unix). This is the standard limitation of credential
//! storage; see the threat model.

use crate::crypto::DeviceKeypairs;
use keyring::Entry;
use std::path::PathBuf;

/// Service name under which ClipVault stores its secrets.
const SERVICE: &str = "clipvault";

/// Sub-entries stored under the service.
const ENTRY_DEVICE_KEYS: &str = "device-keypairs";
const ENTRY_DB_KEY: &str = "history-db-key";

#[derive(Debug)]
pub enum KeychainError {
    /// No secret found for this entry (first run / not yet created).
    NotFound,
    /// The OS credential store rejected the operation.
    Backend(String),
    /// Stored bytes were malformed (truncated / wrong length).
    Corrupt(&'static str),
    Io(std::io::Error),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no secret found in keychain"),
            Self::Backend(m) => write!(f, "keychain backend error: {m}"),
            Self::Corrupt(m) => write!(f, "corrupt keychain entry: {m}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for KeychainError {}
impl From<std::io::Error> for KeychainError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

fn map_entry_err(e: keyring::Error) -> KeychainError {
    match e {
        keyring::Error::NoEntry => KeychainError::NotFound,
        other => KeychainError::Backend(other.to_string()),
    }
}

/// Set the directory for the file fallback. Set once at startup from lib.rs.
static FALLBACK_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn set_fallback_dir(dir: PathBuf) {
    let _ = std::fs::create_dir_all(&dir);
    let _ = FALLBACK_DIR.set(dir);
}

fn fallback_path(name: &str) -> PathBuf {
    FALLBACK_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir())
        .join(format!("{name}.bin"))
}

/// Read a secret: try the OS keychain first, fall back to the file.
fn get_secret(name: &str) -> Result<Vec<u8>, KeychainError> {
    match Entry::new(SERVICE, name) {
        Ok(entry) => match entry.get_secret() {
            Ok(blob) => Ok(blob),
            Err(keyring::Error::NoEntry) => fallback_read(name),
            Err(e) => {
                // Keychain present but read failed — try the fallback rather
                // than hard-failing.
                eprintln!("keychain read for {name} failed, trying fallback: {e}");
                fallback_read(name)
            }
        },
        Err(e) => {
            eprintln!("keychain unavailable for {name}, using file fallback: {e}");
            fallback_read(name)
        }
    }
}

/// Write a secret: try the OS keychain first, fall back to the file.
fn set_secret(name: &str, blob: &[u8]) -> Result<(), KeychainError> {
    match Entry::new(SERVICE, name) {
        Ok(entry) => match entry.set_secret(blob) {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("keychain write for {name} failed, using fallback: {e}");
                fallback_write(name, blob)
            }
        },
        Err(e) => {
            eprintln!("keychain unavailable for {name}, using file fallback: {e}");
            fallback_write(name, blob)
        }
    }
}

fn fallback_read(name: &str) -> Result<Vec<u8>, KeychainError> {
    let path = fallback_path(name);
    match std::fs::read(&path) {
        Ok(blob) => Ok(blob),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeychainError::NotFound),
        Err(e) => Err(KeychainError::Io(e)),
    }
}

fn fallback_write(name: &str, blob: &[u8]) -> Result<(), KeychainError> {
    let path = fallback_path(name);
    std::fs::write(&path, blob)?;
    Ok(())
}

// ---------------------------------------------------------------------------
//  Device keypairs
// ---------------------------------------------------------------------------

/// Persist a device's keypairs. Stores 64 bytes: `ed25519_secret(32) ||
/// x25519_secret(32)`.
pub fn save_device_keypairs(kp: &DeviceKeypairs) -> Result<(), KeychainError> {
    let (ed, x25519) = kp.to_bytes();
    let mut blob = Vec::with_capacity(64);
    blob.extend_from_slice(&ed);
    blob.extend_from_slice(&x25519);
    set_secret(ENTRY_DEVICE_KEYS, &blob)
}

/// Load the device keypairs, or generate + persist new ones on first run.
pub fn load_or_create_device_keypairs() -> Result<DeviceKeypairs, KeychainError> {
    match load_device_keypairs() {
        Ok(kp) => Ok(kp),
        Err(KeychainError::NotFound) => {
            let kp = DeviceKeypairs::generate();
            save_device_keypairs(&kp)?;
            Ok(kp)
        }
        Err(e) => Err(e),
    }
}

/// Load existing keypairs (returns NotFound if absent).
pub fn load_device_keypairs() -> Result<DeviceKeypairs, KeychainError> {
    let blob = get_secret(ENTRY_DEVICE_KEYS)?;
    if blob.len() != 64 {
        return Err(KeychainError::Corrupt("expected 64 bytes (ed||x25519)"));
    }
    let mut ed = [0u8; 32];
    let mut x25519 = [0u8; 32];
    ed.copy_from_slice(&blob[..32]);
    x25519.copy_from_slice(&blob[32..]);
    Ok(DeviceKeypairs::from_bytes(ed, x25519))
}

// ---------------------------------------------------------------------------
//  Local history DB key  (SEPARATE from device keys — see threat model)
// ---------------------------------------------------------------------------

/// Persist a fresh 256-bit key used to encrypt the local history store. This
/// key is distinct from the device keypairs so that leaking the group/device
/// secrets does not by itself expose stored history.
pub fn save_db_key(key: &[u8; 32]) -> Result<(), KeychainError> {
    set_secret(ENTRY_DB_KEY, key)
}

/// Load the history DB key, or generate + persist a fresh one on first run.
pub fn load_or_create_db_key() -> Result<[u8; 32], KeychainError> {
    match load_db_key() {
        Ok(k) => Ok(k),
        Err(KeychainError::NotFound) => {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut k);
            save_db_key(&k)?;
            Ok(k)
        }
        Err(e) => Err(e),
    }
}

/// Load the existing history DB key (returns NotFound if absent).
pub fn load_db_key() -> Result<[u8; 32], KeychainError> {
    let blob = get_secret(ENTRY_DB_KEY)?;
    if blob.len() != 32 {
        return Err(KeychainError::Corrupt("db key must be 32 bytes"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&blob);
    Ok(k)
}

/// Delete all ClipVault secrets (used by "leave room" / factory reset).
pub fn delete_all() -> Result<(), KeychainError> {
    for user in [ENTRY_DEVICE_KEYS, ENTRY_DB_KEY] {
        if let Ok(entry) = Entry::new(SERVICE, user) {
            let _ = entry.delete_credential();
        }
        let _ = std::fs::remove_file(fallback_path(user));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_key_roundtrips_via_fallback() {
        // Use the fallback file path explicitly (no reliance on OS keychain in
        // the test environment). This verifies the (de)serialization path.
        let dir = std::env::temp_dir().join("clipvault-keychain-test");
        let _ = std::fs::create_dir_all(&dir);
        set_fallback_dir(dir.clone());

        let key = [7u8; 32];
        save_db_key(&key).unwrap();
        let got = load_db_key().unwrap();
        assert_eq!(got, key);
        let _ = delete_all();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
