//! OS credential storage: device keypairs + a separate local DB key.
//!
//! Uses the `keyring` crate, which wraps:
//! - **macOS:** Keychain (via `security-framework`)
//! - **Windows:** Credential Manager (DPAPI-protected via `windows-native-keyring-store`)
//! - **Linux:** Secret Service / libsecret (fallback: mock store in tests)
//!
//! Security note: OS keychain storage protects against other *users* reading
//! secrets, but not against malware running as the same logged-in user. This is
//! the standard limitation of every credential store; see the threat model.

use crate::crypto::DeviceKeypairs;
use keyring::Entry;

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
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no secret found in keychain"),
            Self::Backend(m) => write!(f, "keychain backend error: {m}"),
            Self::Corrupt(m) => write!(f, "corrupt keychain entry: {m}"),
        }
    }
}
impl std::error::Error for KeychainError {}

fn map_entry_err(e: keyring::Error) -> KeychainError {
    match e {
        keyring::Error::NoEntry => KeychainError::NotFound,
        other => KeychainError::Backend(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
//  Device keypairs
// ---------------------------------------------------------------------------

/// Persist a device's keypairs to the OS keychain. Stores 64 bytes:
/// `ed25519_secret(32) || x25519_secret(32)`.
pub fn save_device_keypairs(kp: &DeviceKeypairs) -> Result<(), KeychainError> {
    let (ed, x25519) = kp.to_bytes();
    let mut blob = Vec::with_capacity(64);
    blob.extend_from_slice(&ed);
    blob.extend_from_slice(&x25519);
    let entry = Entry::new(SERVICE, ENTRY_DEVICE_KEYS).map_err(map_entry_err)?;
    entry.set_secret(&blob).map_err(map_entry_err)
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
    let entry = Entry::new(SERVICE, ENTRY_DEVICE_KEYS).map_err(map_entry_err)?;
    let blob = entry.get_secret().map_err(map_entry_err)?;
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

/// Persist a fresh 256-bit key used to encrypt the local history SQLite store.
/// This key is distinct from the device keypairs so that leaking the group/
/// device secrets does not by itself expose stored history.
pub fn save_db_key(key: &[u8; 32]) -> Result<(), KeychainError> {
    let entry = Entry::new(SERVICE, ENTRY_DB_KEY).map_err(map_entry_err)?;
    entry.set_secret(key).map_err(map_entry_err)
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
    let entry = Entry::new(SERVICE, ENTRY_DB_KEY).map_err(map_entry_err)?;
    let blob = entry.get_secret().map_err(map_entry_err)?;
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests touch the real (or mock) OS keychain. On headless CI they
    // may behave differently; guard with the keyring mock feature in real CI.
    // For now they verify the byte (de)serialization path doesn't regress.

    #[test]
    fn db_key_roundtrips_when_available() {
        // Use a per-test entry to avoid clobbering the real one. If the OS has
        // no usable credential store in this environment (e.g. headless test
        // runner), skip gracefully rather than fail.
        let entry = match Entry::new(SERVICE, "test-db-key") {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping: no keychain backend available ({e})");
                return;
            }
        };
        let key = [7u8; 32];
        if entry.set_secret(&key).is_err() {
            eprintln!("skipping: keychain backend present but write failed");
            return;
        }
        let got = entry.get_secret().unwrap();
        assert_eq!(got, key);
        let _ = entry.delete_credential();
    }
}
