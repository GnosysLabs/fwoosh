//! Shared application state, persisted settings, wire types, and IPC DTOs.

use super::*;
use tauri_plugin_fs::FilePath;

/// App-wide shared state.
pub struct AppState {
    pub device: DeviceKeypairs,
    pub store: HistoryStore,
    /// The current verified roster (None until the device joins/creates a room).
    pub roster: Mutex<Option<VerifiedRoster>>,
    /// ntfy base URL (default public relay; configurable).
    pub ntfy_base: Mutex<String>,
    /// In-flight partial clips keyed by msg_id: (manifest, received chunks).
    pub pending: Mutex<HashMap<[u8; 16], PendingClip>>,
    /// Last ntfy message id per topic, for `since=` catch-up.
    pub last_msg_ids: Mutex<HashMap<String, String>>,
    /// Handle to the subscriber task (so we can shut it down on topic change).
    pub subscriber_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Durable, reusable invitations loaded from the OS keychain.
    pub invitations: Mutex<HashMap<String, InvitationRecord>>,
    /// Valid v2 requests waiting for an explicit admin decision.
    pub pending_joins: Mutex<HashMap<String, PendingJoinRecord>>,
    /// Joiner-side trust anchor while waiting for the admin's encrypted grant.
    pub pending_network_join: Mutex<Option<PendingNetworkJoin>>,
    /// Invitation and pending-join subscribers run alongside the room subscriber.
    pub auxiliary_subscriber_shutdowns: Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>,
    /// Path to the persisted roster file (set at startup).
    pub roster_path: Mutex<Option<std::path::PathBuf>>,
    /// Directory containing one verified roster chain per sync group.
    pub groups_dir: Mutex<Option<std::path::PathBuf>>,
    /// Path to app settings JSON (set at startup).
    pub settings_path: Mutex<Option<std::path::PathBuf>>,
    /// Local user settings such as display label and STUN servers.
    pub settings: Mutex<AppSettings>,
    /// Active large-file transfer sessions keyed by session_id.
    pub file_transfers: Mutex<HashMap<String, TransferRecord>>,
    /// Successfully received file paths, keyed by transfer id and kept only
    /// for the lifetime of this process. Reveal requests must match this
    /// backend-owned allowlist, so the UI cannot open an arbitrary path.
    pub completed_received_files: Mutex<VecDeque<(String, PathBuf)>>,
    /// Short-lived OS file-drop grants keyed by an unguessable id.
    pub file_grants: Mutex<HashMap<String, FileGrant>>,
}

/// A partially-received clip awaiting all its chunks.
pub struct PendingClip {
    pub(crate) manifest: crypto::Manifest,
    pub(crate) chunks: Vec<Option<crypto::Chunk>>,
}

pub struct FileGrant {
    pub(crate) path: PathBuf,
    pub(crate) created_at: u64,
}

impl AppState {
    pub fn new(device: DeviceKeypairs, store: HistoryStore) -> Self {
        Self {
            device,
            store,
            roster: Mutex::new(None),
            ntfy_base: Mutex::new(ntfy::DEFAULT_BASE.to_string()),
            pending: Mutex::new(HashMap::new()),
            last_msg_ids: Mutex::new(HashMap::new()),
            subscriber_shutdown: Mutex::new(None),
            invitations: Mutex::new(HashMap::new()),
            pending_joins: Mutex::new(HashMap::new()),
            pending_network_join: Mutex::new(None),
            auxiliary_subscriber_shutdowns: Mutex::new(HashMap::new()),
            roster_path: Mutex::new(None),
            groups_dir: Mutex::new(None),
            settings_path: Mutex::new(None),
            settings: Mutex::new(AppSettings::default()),
            file_transfers: Mutex::new(HashMap::new()),
            completed_received_files: Mutex::new(VecDeque::new()),
            file_grants: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSettings {
    pub device_label: Option<String>,
    pub stun_servers: Vec<String>,
    #[serde(default = "default_file_transfer_timeout_minutes")]
    pub transfer_timeout_minutes: u64,
    #[serde(default)]
    pub sync_groups: Vec<SyncGroupConfig>,
    #[serde(default)]
    pub active_sync_group_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncGroupConfig {
    pub id: String,
    pub name: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            device_label: None,
            stun_servers: vec![DEFAULT_STUN_SERVER.to_string()],
            transfer_timeout_minutes: DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES,
            sync_groups: Vec::new(),
            active_sync_group_id: None,
        }
    }
}

#[derive(Serialize)]
pub struct SyncGroupDto {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub connected: bool,
    pub member_count: usize,
}

#[derive(Serialize)]
pub struct NetworkSettingsDto {
    pub stun_servers: Vec<String>,
    pub transfer_timeout_minutes: u64,
}

#[derive(Serialize)]
pub struct PairingCodeDto {
    pub uri: String,
    pub invite_id: String,
    pub network_id: String,
    pub expires_at: Option<u64>,
    pub is_permanent: bool,
}

#[derive(Clone)]
pub struct PendingJoinRecord {
    pub request_id: String,
    pub network_id: String,
    pub rendezvous_topic: String,
    pub request: crate::pairing::NetworkJoinRequest,
    pub received_at: u64,
}

#[derive(Clone)]
pub struct PendingNetworkJoin {
    pub invite_id: String,
    pub rendezvous_topic: String,
    pub admin_pub: crypto::Ed25519PubKey,
    pub requested_at: u64,
}

#[derive(Clone, Serialize)]
pub struct PendingJoinDto {
    pub request_id: String,
    pub invite_id: String,
    pub network_id: String,
    pub label: String,
    pub fingerprint: String,
    pub received_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PairingJoinEnvelope {
    pub invite_id: String,
    pub sealed: crypto::BootstrapCiphertext,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PairingRosterGrant {
    pub invite_id: String,
    pub recipient_id: crypto::Ed25519PubKey,
    pub sealed: crypto::BootstrapCiphertext,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PairingRosterPayload {
    pub(crate) network_id: String,
    pub(crate) network_name: String,
    pub(crate) roster_chain: Vec<roster::RosterEntry>,
}

pub enum TransferRecord {
    PendingIncoming(PendingIncomingTransfer),
    Outgoing(OutgoingTransfer),
    Incoming(IncomingTransfer),
}

#[derive(Clone)]
pub struct PendingIncomingTransfer {
    pub(crate) sender_id: crypto::Ed25519PubKey,
    pub(crate) file_name: String,
    pub(crate) size: u64,
    pub(crate) content_key: [u8; 32],
    pub(crate) nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
    pub(crate) offer_sdp_json: String,
    pub(crate) timeout_token: u64,
}

pub struct OutgoingTransfer {
    pub(crate) recipient_id: crypto::Ed25519PubKey,
    pub(crate) peer: Arc<RTCPeerConnection>,
    pub(crate) timeout_token: u64,
}

pub struct IncomingTransfer {
    pub(crate) sender_id: crypto::Ed25519PubKey,
    pub(crate) peer: Arc<RTCPeerConnection>,
    pub(crate) part_path: PathBuf,
    pub(crate) timeout_token: u64,
}

#[derive(Clone, Serialize)]
pub struct TransferDto {
    pub session_id: String,
    pub file_name: String,
    pub size: u64,
    pub peer_label: String,
    pub direction: String,
    pub status: String,
}

#[derive(Clone, Serialize)]
pub struct FileOfferDto {
    pub session_id: String,
    pub sender_id: String,
    pub sender_label: String,
    pub file_name: String,
    pub size: u64,
}

#[derive(Clone, Serialize)]
pub struct FileTransferProgressDto {
    pub session_id: String,
    pub transferred: u64,
    pub total: u64,
    pub status: String,
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct FileDropGrantDto {
    pub grant_id: String,
    pub file_name: String,
    pub size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum FileSignal {
    Offer {
        session_id: String,
        file_name: String,
        size: u64,
        content_key: [u8; 32],
        nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
        sdp_json: String,
    },
    Answer {
        session_id: String,
        sdp_json: String,
    },
    Reject {
        session_id: String,
        reason: String,
    },
    Cancel {
        session_id: String,
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum FileFrame {
    Chunk {
        index: u64,
        ct: Vec<u8>,
    },
    /// Carries the checksum of the plaintext stream. Keeping it in the final
    /// authenticated frame lets the sender calculate it while streaming rather
    /// than making a full pre-transfer pass over the file.
    Finish {
        sha256: [u8; 32],
    },
    Cancel {
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct PersistedRosterChain {
    pub(crate) version: u8,
    pub(crate) entries: Vec<roster::RosterEntry>,
}

pub struct ReceiverWriteState {
    pub(crate) session_id: String,
    pub(crate) file_name: String,
    pub(crate) total: u64,
    pub(crate) received: u64,
    pub(crate) next_index: u64,
    pub(crate) content_key: [u8; 32],
    pub(crate) nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
    pub(crate) file: Option<tokio::fs::File>,
    /// Desktop destinations are ordinary paths. Mobile save dialogs can
    /// return provider URIs, which are copied to only after verification.
    pub(crate) final_path: Option<PathBuf>,
    pub(crate) final_destination: Option<FilePath>,
    pub(crate) part_path: PathBuf,
    pub(crate) hasher: Sha256,
    pub(crate) done: bool,
}

#[derive(Clone)]
pub struct OutgoingFilePayload {
    pub(crate) path: FilePath,
    pub(crate) file_name: String,
    pub(crate) total: u64,
    pub(crate) content_key: [u8; 32],
    pub(crate) nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
}

// ---- Wire message kinds (postcard-encoded, then base64 by ntfy.rs) ----

/// A message published to the relay. Either a clip manifest, a chunk, a
/// roster epoch broadcast, or a join request. Distinguished by a tag byte.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum WireMessage {
    /// Tag 0: a clip manifest (published first).
    Manifest(crypto::Manifest),
    /// Tag 1: a clip chunk (references msg_id).
    Chunk(crypto::Chunk),
    /// Tag 2: a roster epoch broadcast (signed, tamper-evident).
    Roster(roster::RosterEntry),
    /// Tag 3: a signed request to delete a history row for a clip message.
    DeleteClip(DeleteClipMessage),
    /// Tag 4: a signed request to rename the sender's roster label.
    RenameDevice(RenameDeviceMessage),
    /// Tag 5: encrypted reusable-invitation join request.
    PairingJoin(PairingJoinEnvelope),
    /// Tag 6: encrypted approved roster snapshot for one joining device.
    PairingGrant(PairingRosterGrant),
    /// Tag 7: signed manifest whose encrypted chunks are in an ntfy attachment.
    ClipAttachment(crypto::Manifest),
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct DeleteClipMessage {
    pub msg_id: [u8; 16],
    pub room_id: String,
    pub roster_epoch: u64,
    pub sender_id: crypto::Ed25519PubKey,
    pub ts: u64,
    pub signature: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct RenameDeviceMessage {
    pub device_id: crypto::Ed25519PubKey,
    pub room_id: String,
    pub roster_epoch: u64,
    pub label: String,
    pub ts: u64,
    pub signature: Vec<u8>,
}
