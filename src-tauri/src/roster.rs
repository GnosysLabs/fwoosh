//! The roster: an append-only, hash-chained, admin-signed log of device
//! membership (the security core's "who is allowed").
//!
//! Design (frozen spec):
//! - Each entry (an "epoch") records the full device list + revoked list and
//!   is signed by the **admin** device's Ed25519 key.
//! - Entries are hash-chained: `prev_hash = SHA-256(postcard(previous_entry))`.
//! - Epoch 0 is the genesis entry (admin only). Adds/revokes bump the epoch.
//! - v1 rule: **admin-only mutation**. Only the admin can sign new epochs.
//!   If the admin device is lost, the escape is a new room (re-pair all).
//! - Revocation appends a revoke entry AND rotates the ntfy topic, so a removed
//!   device can no longer watch metadata or spam the topic.
//! - Every clip pins a roster epoch; receivers reject stale/unknown epochs
//!   (see `crypto::open_clip`).
//!
//! On the wire, roster entries are broadcast (encrypted) and each device caches
//! the latest verified epoch locally.

use crate::crypto::{DeviceKeypairs, Ed25519PubKey, X25519PubKey};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for roster signatures (distinct from envelope signatures).
const ROSTER_SIG_DOMAIN: &[u8] = b"Fwoosh roster v1";

/// A device's public identity in the roster.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub signing_pub: Ed25519PubKey,
    pub x25519_pub: X25519PubKey,
    /// Human-readable label set by the device (e.g. "Aramo's MacBook").
    pub label: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("signing_pub", &hex::encode(self.signing_pub.0))
            .field("x25519_pub", &hex::encode(self.x25519_pub.0))
            .field("label", &self.label)
            .finish()
    }
}

impl DeviceIdentity {
    pub fn from_keypairs(kp: &DeviceKeypairs, label: &str) -> Self {
        Self {
            signing_pub: kp.signing_pub.clone(),
            x25519_pub: kp.x25519_pub.clone(),
            label: label.to_string(),
        }
    }
}

#[derive(Debug)]
pub enum RosterError {
    /// The signature on the entry did not verify.
    InvalidSignature,
    /// The prev_hash doesn't match the expected previous entry's hash.
    ChainBroken { epoch: u64 },
    /// The signer is not the admin.
    NotAdmin,
    /// A newer epoch is already known; this entry is stale.
    Stale { got: u64, have: u64 },
    /// The epoch number isn't sequential (gap or repeat).
    BadEpoch { got: u64, expected: u64 },
    /// A device appears in both the active and revoked lists.
    InconsistentMembership,
    /// Bad input.
    BadInput(&'static str),
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "roster signature verification failed"),
            Self::ChainBroken { epoch } => write!(f, "hash chain broken at epoch {epoch}"),
            Self::NotAdmin => write!(f, "only the admin may sign roster epochs"),
            Self::Stale { got, have } => write!(f, "stale epoch {got} (have {have})"),
            Self::BadEpoch { got, expected } => {
                write!(f, "bad epoch {got} (expected {expected})")
            }
            Self::InconsistentMembership => {
                write!(f, "a device is both active and revoked")
            }
            Self::BadInput(m) => write!(f, "bad input: {m}"),
        }
    }
}
impl std::error::Error for RosterError {}

/// One signed epoch in the membership log.
#[derive(Clone, Serialize, Deserialize)]
pub struct RosterEntry {
    /// Monotonically increasing epoch number (0 = genesis).
    pub epoch: u64,
    /// Hash of the previous entry's canonical bytes (all-zero for epoch 0).
    pub prev_hash: [u8; 32],
    /// The ntfy topic to use from this epoch onward. Rotated on revoke so a
    /// removed device can't keep watching/spamming.
    pub topic: String,
    /// Currently active members (incl. admin).
    pub devices: Vec<DeviceIdentity>,
    /// Members removed in or before this epoch (kept for history/repair UX).
    pub revoked: Vec<DeviceIdentity>,
    /// The admin's Ed25519 pubkey (stable across epochs; admin transfer is
    /// out of v1 scope).
    pub admin_id: Ed25519PubKey,
    /// Ed25519 signature over `ROSTER_SIG_DOMAIN || postcard(Self without sig)`.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for RosterEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RosterEntry")
            .field("epoch", &self.epoch)
            .field("prev_hash", &hex::encode(self.prev_hash))
            .field("topic", &self.topic)
            .field("devices", &self.devices.len())
            .field("revoked", &self.revoked.len())
            .field("admin_id", &hex::encode(self.admin_id.0))
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

/// Entry minus the signature, for canonical signing.
#[derive(Serialize)]
struct RosterEntryForSigning<'a> {
    epoch: u64,
    prev_hash: &'a [u8; 32],
    topic: &'a str,
    devices: &'a [DeviceIdentity],
    revoked: &'a [DeviceIdentity],
    admin_id: &'a Ed25519PubKey,
}

fn canonical_bytes(e: &RosterEntry) -> Vec<u8> {
    let view = RosterEntryForSigning {
        epoch: e.epoch,
        prev_hash: &e.prev_hash,
        topic: &e.topic,
        devices: &e.devices,
        revoked: &e.revoked,
        admin_id: &e.admin_id,
    };
    let mut buf = ROSTER_SIG_DOMAIN.to_vec();
    buf.extend_from_slice(&postcard::to_allocvec(&view).expect("postcard encode roster"));
    buf
}

/// SHA-256 of an entry's canonical bytes (used to chain the next entry).
pub fn entry_hash(e: &RosterEntry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&canonical_bytes(e));
    h.finalize().into()
}

fn verify_entry_sig(e: &RosterEntry) -> Result<(), RosterError> {
    let vk = VerifyingKey::from_bytes(&e.admin_id.0)
        .map_err(|_| RosterError::BadInput("bad admin ed25519 pubkey"))?;
    let sig = Signature::from_slice(&e.signature)
        .map_err(|_| RosterError::BadInput("bad signature bytes"))?;
    vk.verify(&canonical_bytes(e), &sig)
        .map_err(|_| RosterError::InvalidSignature)
}

/// Verify only the signature + internal consistency of an entry, without
/// checking the chain (no previous entry needed). Used by the joiner path
/// when it adopts a roster it didn't chain-verify.
pub fn verify_entry_sig_only(e: &RosterEntry) -> Result<(), RosterError> {
    VerifiedRoster::check_consistency(e)?;
    verify_entry_sig(e)
}

// ===========================================================================
//  A verified view of a roster entry + helpers to advance the chain.
//  Mutations are admin-only and always produce a NEW epoch.
// ===========================================================================

/// Verified state of one roster epoch. Constructed only via verification, so
/// holders can trust the signature + chain integrity (but should still check
/// epoch freshness against their cached latest).
#[derive(Clone, Debug)]
pub struct VerifiedRoster {
    pub entry: RosterEntry,
}

impl VerifiedRoster {
    /// Verify a standalone entry's signature + internal consistency.
    /// (Chain continuity against a previous entry is checked by
    /// `verify_next`.)
    pub fn verify_first(entry: RosterEntry) -> Result<Self, RosterError> {
        if entry.epoch != 0 {
            return Err(RosterError::BadEpoch { got: entry.epoch, expected: 0 });
        }
        if entry.prev_hash != [0u8; 32] {
            return Err(RosterError::ChainBroken { epoch: 0 });
        }
        Self::check_consistency(&entry)?;
        verify_entry_sig(&entry)?;
        Ok(Self { entry })
    }

    /// Construct a VerifiedRoster from an entry whose signature has already
    /// been checked (via `verify_entry_sig_only`). Used by the joiner path
    /// when it receives a non-genesis roster as its first entry (it missed the
    /// genesis broadcast). The chain can't be verified without the previous
    /// entry, but the admin's signature is the trust root.
    pub fn from_entry(entry: RosterEntry) -> Self {
        Self { entry }
    }

    /// Verify that `next` is a valid successor to `self`: sequential epoch,
    /// correct prev_hash, admin-signed, internally consistent.
    pub fn verify_next(&self, next: RosterEntry) -> Result<Self, RosterError> {
        let expected_epoch = self.entry.epoch + 1;
        if next.epoch != expected_epoch {
            return Err(RosterError::BadEpoch {
                got: next.epoch,
                expected: expected_epoch,
            });
        }
        let expected_prev = entry_hash(&self.entry);
        if next.prev_hash != expected_prev {
            return Err(RosterError::ChainBroken { epoch: next.epoch });
        }
        if next.admin_id != self.entry.admin_id {
            return Err(RosterError::NotAdmin);
        }
        Self::check_consistency(&next)?;
        verify_entry_sig(&next)?;
        Ok(Self { entry: next })
    }

    /// True if `device_id` is an active (non-revoked) member.
    pub fn is_active(&self, device_id: &Ed25519PubKey) -> bool {
        self.entry.devices.iter().any(|d| &d.signing_pub == device_id)
    }

    /// Active members as `Recipient`s (for `crypto::seal_clip`).
    pub fn recipients(&self) -> Vec<crate::crypto::Recipient> {
        self.entry
            .devices
            .iter()
            .map(|d| crate::crypto::Recipient {
                id: d.signing_pub.clone(),
                x25519: d.x25519_pub.clone(),
            })
            .collect()
    }

    /// The current topic.
    pub fn topic(&self) -> &str {
        &self.entry.topic
    }

    /// Current epoch number.
    pub fn epoch(&self) -> u64 {
        self.entry.epoch
    }

    fn check_consistency(e: &RosterEntry) -> Result<(), RosterError> {
        if e.devices.is_empty() {
            return Err(RosterError::BadInput("no active devices"));
        }
        // Admin must be in the active device list.
        if !e.devices.iter().any(|d| &d.signing_pub == &e.admin_id) {
            return Err(RosterError::BadInput("admin not in active devices"));
        }
        // No device may be both active and revoked.
        for r in &e.revoked {
            if e.devices.iter().any(|d| d.signing_pub == r.signing_pub) {
                return Err(RosterError::InconsistentMembership);
            }
        }
        Ok(())
    }
}

// ===========================================================================
//  Admin-side mutation helpers (only the admin device calls these). Each
//  returns an UNSIGNED entry that the admin then signs with sign_entry().
// ===========================================================================

/// Build the genesis (epoch 0) entry. Called once by the room creator (admin).
pub fn build_genesis(admin: &DeviceKeypairs, admin_label: &str, topic: &str) -> RosterEntry {
    let admin_id = admin.signing_pub.clone();
    let devices = vec![DeviceIdentity::from_keypairs(admin, admin_label)];
    RosterEntry {
        epoch: 0,
        prev_hash: [0u8; 32],
        topic: topic.to_string(),
        devices,
        revoked: Vec::new(),
        admin_id,
        signature: Vec::new(),
    }
}

/// Build a new epoch that ADDS a device. Admin signs; prev_hash/topic filled in.
pub fn build_add_device(prev: &RosterEntry, new_device: DeviceIdentity) -> RosterEntry {
    let mut devices = prev.devices.clone();
    // Avoid duplicates / re-adding a revoked device without clearing revocation.
    devices.retain(|d| d.signing_pub != new_device.signing_pub);
    devices.push(new_device);
    RosterEntry {
        epoch: prev.epoch + 1,
        prev_hash: [0u8; 32], // filled by sign_and_chain
        topic: prev.topic.clone(),
        devices,
        revoked: prev.revoked.clone(),
        admin_id: prev.admin_id.clone(),
        signature: Vec::new(),
    }
}

/// Build a new epoch that REVOKES a device AND rotates the topic. Returns the
/// unsigned entry; the caller should also publish the new topic to remaining
/// members so they can resubscribe.
pub fn build_revoke_device(
    prev: &RosterEntry,
    revoked_id: &Ed25519PubKey,
    new_topic: &str,
) -> Result<RosterEntry, RosterError> {
    let victim = prev
        .devices
        .iter()
        .find(|d| &d.signing_pub == revoked_id)
        .ok_or(RosterError::BadInput("device to revoke is not active"))?
        .clone();

    if revoked_id == &prev.admin_id {
        return Err(RosterError::BadInput("cannot revoke the admin (transfer is out of v1)"));
    }

    let devices: Vec<DeviceIdentity> = prev
        .devices
        .iter()
        .filter(|d| &d.signing_pub != revoked_id)
        .cloned()
        .collect();
    let mut revoked = prev.revoked.clone();
    revoked.retain(|d| d.signing_pub != victim.signing_pub);
    revoked.push(victim);

    Ok(RosterEntry {
        epoch: prev.epoch + 1,
        prev_hash: [0u8; 32],
        topic: new_topic.to_string(),
        devices,
        revoked,
        admin_id: prev.admin_id.clone(),
        signature: Vec::new(),
    })
}

/// Sign an unsigned entry and fill in its prev_hash from `prev` (None for
/// genesis). Consumes the unsigned entry and returns the signed one.
pub fn sign_and_chain(
    admin: &DeviceKeypairs,
    mut entry: RosterEntry,
    prev: Option<&RosterEntry>,
) -> Result<RosterEntry, RosterError> {
    if admin.signing_pub != entry.admin_id {
        return Err(RosterError::NotAdmin);
    }
    entry.prev_hash = match prev {
        Some(p) => entry_hash(p),
        None => {
            if entry.epoch != 0 {
                return Err(RosterError::BadEpoch { got: entry.epoch, expected: 0 });
            }
            [0u8; 32]
        }
    };
    let bytes = canonical_bytes(&entry);
    entry.signature = admin.signing.sign(&bytes).to_bytes().to_vec();
    // Verify our own signature before returning (defense in depth).
    verify_entry_sig(&entry)?;
    Ok(entry)
}

/// Generate a fresh, unguessable ntfy topic name (~190 bits of entropy).
pub fn new_topic() -> String {
    let mut buf = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    // url-safe base64 without padding
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

// ===========================================================================
//  Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_admin() -> DeviceKeypairs { DeviceKeypairs::generate() }

    fn genesis(admin: &DeviceKeypairs, topic: &str) -> RosterEntry {
        let unsigned = build_genesis(admin, "admin-laptop", topic);
        sign_and_chain(admin, unsigned, None).unwrap()
    }

    #[test]
    fn genesis_verifies() {
        let admin = gen_admin();
        let topic = new_topic();
        let g = genesis(&admin, &topic);
        let v = VerifiedRoster::verify_first(g).unwrap();
        assert_eq!(v.epoch(), 0);
        assert_eq!(v.topic(), topic);
        assert!(v.is_active(&admin.signing_pub));
        assert_eq!(v.entry.devices.len(), 1);
    }

    #[test]
    fn add_device_advances_epoch_and_chain() {
        let admin = gen_admin();
        let g = genesis(&admin, &new_topic());
        let v0 = VerifiedRoster::verify_first(g.clone()).unwrap();

        let bob = DeviceKeypairs::generate();
        let bob_id = DeviceIdentity::from_keypairs(&bob, "bob-pc");
        let unsigned = build_add_device(&g, bob_id);
        let signed = sign_and_chain(&admin, unsigned, Some(&g)).unwrap();
        let v1 = v0.verify_next(signed).unwrap();
        assert_eq!(v1.epoch(), 1);
        assert_eq!(v1.entry.devices.len(), 2);
        assert!(v1.is_active(&bob.signing_pub));
    }

    #[test]
    fn revoke_removes_device_and_rotates_topic() {
        let admin = gen_admin();
        let bob = DeviceKeypairs::generate();
        let bob_id = DeviceIdentity::from_keypairs(&bob, "bob-pc");
        let topic0 = new_topic();
        let g = genesis(&admin, &topic0);
        let v0 = VerifiedRoster::verify_first(g.clone()).unwrap();

        // epoch 1: add bob
        let e1 = sign_and_chain(&admin, build_add_device(&g, bob_id.clone()), Some(&g)).unwrap();
        let v1 = v0.verify_next(e1.clone()).unwrap();
        assert!(v1.is_active(&bob.signing_pub));

        // epoch 2: revoke bob + rotate topic
        let topic2 = new_topic();
        assert_ne!(topic0, topic2);
        let e2_unsigned = build_revoke_device(&e1, &bob.signing_pub, &topic2).unwrap();
        let e2 = sign_and_chain(&admin, e2_unsigned, Some(&e1)).unwrap();
        let v2 = v1.verify_next(e2).unwrap();
        assert_eq!(v2.epoch(), 2);
        assert_eq!(v2.topic(), topic2);
        assert!(!v2.is_active(&bob.signing_pub));
        assert_eq!(v2.entry.devices.len(), 1);
        assert_eq!(v2.entry.revoked.len(), 1);
    }

    #[test]
    fn forged_epoch_rejected() {
        let admin = gen_admin();
        let mallory = gen_admin(); // different admin key
        let g_unsigned = build_genesis(&admin, "real-admin", &new_topic());
        // Mallory signs with her own key but keeps admin_id = real admin.
        let mut forged = g_unsigned;
        forged.signature = mallory.signing.sign(&canonical_bytes(&forged)).to_bytes().to_vec();
        let err = VerifiedRoster::verify_first(forged).unwrap_err();
        assert!(matches!(err, RosterError::InvalidSignature), "got {err:?}");
    }

    #[test]
    fn broken_chain_rejected() {
        let admin = gen_admin();
        let g = genesis(&admin, &new_topic());
        // (genesis verified implicitly via genesis() -> sign_and_chain)

        // Build epoch 1 from genesis, but then try to verify it as a successor
        // of a *different* (tampered) genesis -> prev_hash mismatch.
        let bob = DeviceKeypairs::generate();
        let e1 = sign_and_chain(
            &admin,
            build_add_device(&g, DeviceIdentity::from_keypairs(&bob, "b")),
            Some(&g),
        )
        .unwrap();
        // Tamper genesis topic (re-signing wouldn't help since hash changes);
        // instead simulate by making a second genesis with a different topic.
        let g2 = genesis(&admin, &new_topic());
        let v0b = VerifiedRoster::verify_first(g2).unwrap();
        let err = v0b.verify_next(e1).unwrap_err();
        assert!(matches!(err, RosterError::ChainBroken { .. }), "got {err:?}");
    }

    #[test]
    fn non_admin_cannot_sign() {
        let admin = gen_admin();
        let bob = gen_admin();
        let g = build_genesis(&admin, "admin", &new_topic());
        // bob tries to sign an entry whose admin_id is the real admin.
        let err = sign_and_chain(&bob, g, None).unwrap_err();
        assert!(matches!(err, RosterError::NotAdmin), "got {err:?}");
    }

    #[test]
    fn stale_epoch_rejected_by_verify_next() {
        let admin = gen_admin();
        let g = genesis(&admin, &new_topic());
        let v0 = VerifiedRoster::verify_first(g.clone()).unwrap();
        let e1 = sign_and_chain(
            &admin,
            build_add_device(&g, DeviceIdentity::from_keypairs(&gen_admin(), "x")),
            Some(&g),
        )
        .unwrap();
        let v1 = v0.verify_next(e1.clone()).unwrap();
        // Trying to apply the same epoch again is not a valid successor of v1
        // (v1 expects epoch 2, e1 is epoch 1).
        let err = v1.verify_next(e1).unwrap_err();
        assert!(matches!(err, RosterError::BadEpoch { .. }), "got {err:?}");
    }

    #[test]
    fn cannot_revoke_admin() {
        let admin = gen_admin();
        let g = genesis(&admin, &new_topic());
        let err = build_revoke_device(&g, &admin.signing_pub, &new_topic()).unwrap_err();
        assert!(matches!(err, RosterError::BadInput(_)), "got {err:?}");
    }

    #[test]
    fn recipients_match_active_devices() {
        let admin = gen_admin();
        let bob = DeviceKeypairs::generate();
        let g = genesis(&admin, &new_topic());
        let v0 = VerifiedRoster::verify_first(g.clone()).unwrap();
        let e1 = sign_and_chain(
            &admin,
            build_add_device(&g, DeviceIdentity::from_keypairs(&bob, "bob")),
            Some(&g),
        )
        .unwrap();
        let v1 = v0.verify_next(e1).unwrap();
        let r = v1.recipients();
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|x| x.id == admin.signing_pub));
        assert!(r.iter().any(|x| x.id == bob.signing_pub));
    }
}
