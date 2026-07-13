//! Versioned product-domain types for groups, invitations, and direct contacts.
//!
//! A group is a persistent clipboard-sync trust domain. A Contact (shown as
//! "People" in the UI) is deliberately not a group member and can only be a
//! recipient of an explicit direct share.

use crate::crypto::{Ed25519PubKey, X25519PubKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

pub const NETWORK_STORE_VERSION: u8 = 1;
pub const INVITATION_STORE_VERSION: u8 = 1;
pub const CONTACT_STORE_VERSION: u8 = 1;

pub type NetworkId = String;
pub type InvitationId = String;
pub type ContactId = String;

/// Metadata that remains stable while a group's relay topic rotates.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkMetadata {
    pub id: NetworkId,
    pub name: String,
    pub created_at: u64,
}

/// A durable device-sync invitation owned by a group admin.
///
/// `secret` is serialized only into the OS-keychain-backed invitation blob.
/// It must never be written to ordinary settings or roster files.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationRecord {
    pub id: InvitationId,
    pub network_id: NetworkId,
    pub secret: [u8; 32],
    pub created_at: u64,
    /// `None` means the invitation remains valid until manually revoked.
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl std::fmt::Debug for InvitationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationRecord")
            .field("id", &self.id)
            .field("network_id", &self.network_id)
            .field("secret", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl InvitationRecord {
    pub fn is_active_at(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

/// A direct-share contact. Contacts never appear in a group roster.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactRecord {
    pub id: ContactId,
    pub label: String,
    pub signing_pub: Ed25519PubKey,
    pub x25519_pub: X25519PubKey,
    /// Pairwise relay topic, unrelated to every group topic.
    pub topic: String,
    pub created_at: u64,
}

/// Explicit file/direct-share destinations. Clipboard commands intentionally
/// accept a group `NetworkId` instead of this enum, making `Person` unrepresentable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DirectRecipientRef {
    NetworkDevice {
        network_id: NetworkId,
        device_id: String,
    },
    Person {
        contact_id: ContactId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationStore {
    pub version: u8,
    pub invitations: Vec<InvitationRecord>,
}

impl Default for InvitationStore {
    fn default() -> Self {
        Self {
            version: INVITATION_STORE_VERSION,
            invitations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactStore {
    pub version: u8,
    pub contacts: Vec<ContactRecord>,
}

impl Default for ContactStore {
    fn default() -> Self {
        Self {
            version: CONTACT_STORE_VERSION,
            contacts: Vec::new(),
        }
    }
}

pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_lifetime_is_explicit() {
        let permanent = InvitationRecord {
            id: new_id(),
            network_id: new_id(),
            secret: [7; 32],
            created_at: 100,
            expires_at: None,
            revoked_at: None,
        };
        assert!(permanent.is_active_at(u64::MAX));

        let mut temporary = permanent.clone();
        temporary.expires_at = Some(200);
        assert!(temporary.is_active_at(199));
        assert!(!temporary.is_active_at(200));

        let mut revoked = permanent;
        revoked.revoked_at = Some(150);
        assert!(!revoked.is_active_at(151));
    }

    #[test]
    fn generated_ids_are_valid_and_distinct() {
        let a = new_id();
        let b = new_id();
        assert!(valid_id(&a));
        assert!(valid_id(&b));
        assert_ne!(a, b);
    }
}
