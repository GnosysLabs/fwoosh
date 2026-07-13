use super::*;
use crate::crypto::DeviceKeypairs;
use crate::roster::DeviceIdentity;

fn identity(device: &DeviceKeypairs, label: &str) -> DeviceIdentity {
    DeviceIdentity {
        signing_pub: device.signing_pub.clone(),
        x25519_pub: device.x25519_pub.clone(),
        label: label.to_string(),
    }
}

#[tokio::test]
async fn require_admin_roster_returns_an_owned_verified_roster() {
    let admin = DeviceKeypairs::generate();
    let signed = roster::sign_and_chain(
        &admin,
        roster::build_genesis(&admin, "Admin", "topic"),
        None,
    )
    .unwrap();
    let verified = VerifiedRoster::verify_first(signed).unwrap();
    let state = Arc::new(AppState::new(
        admin,
        HistoryStore::open(Path::new(":memory:"), &[10u8; 32]).unwrap(),
    ));
    *state.roster.lock().await = Some(verified);

    let owned = require_admin_roster(&state, "test authorization")
        .await
        .unwrap();
    assert_eq!(owned.epoch(), 0);
    assert!(state.roster.try_lock().is_ok());
}

#[tokio::test]
async fn require_admin_roster_rejects_a_non_admin_device() {
    let admin = DeviceKeypairs::generate();
    let member = DeviceKeypairs::generate();
    let signed = roster::sign_and_chain(
        &admin,
        roster::build_genesis(&admin, "Admin", "topic"),
        None,
    )
    .unwrap();
    let state = Arc::new(AppState::new(
        member,
        HistoryStore::open(Path::new(":memory:"), &[11u8; 32]).unwrap(),
    ));
    *state.roster.lock().await = Some(VerifiedRoster::verify_first(signed).unwrap());

    assert_eq!(
        require_admin_roster(&state, "test authorization")
            .await
            .unwrap_err(),
        "only the group admin can test authorization"
    );
}

#[test]
fn v2_pairing_request_and_grant_are_confidential_and_verifiable() {
    let admin = DeviceKeypairs::generate();
    let joining = DeviceKeypairs::generate();
    let invite_id = network::new_id();
    let secret = crate::pairing::random_secret();
    let request = crate::pairing::build_network_join_request(
        invite_id.clone(),
        identity(&joining, "Laptop"),
        &secret,
        100,
    );
    let request_bytes = postcard::to_allocvec(&request).unwrap();
    let request_info = pairing_bootstrap_info(&invite_id, "join");
    let sealed_request =
        crypto::seal_bootstrap(&admin.x25519_pub, &request_info, &request_bytes).unwrap();
    let opened_request = crypto::open_bootstrap(&admin, &request_info, &sealed_request).unwrap();
    let decoded_request: crate::pairing::NetworkJoinRequest =
        postcard::from_bytes(&opened_request).unwrap();
    crate::pairing::verify_network_join_request(&decoded_request, &secret).unwrap();

    let topic = roster::new_topic();
    let genesis =
        roster::sign_and_chain(&admin, roster::build_genesis(&admin, "Admin", &topic), None)
            .unwrap();
    let added = roster::sign_and_chain(
        &admin,
        roster::build_add_device(&genesis, decoded_request.identity.clone()),
        Some(&genesis),
    )
    .unwrap();
    let payload = PairingRosterPayload {
        network_id: network::new_id(),
        network_name: "Personal".to_string(),
        roster_chain: vec![genesis, added],
    };
    let grant_bytes = postcard::to_allocvec(&payload).unwrap();
    let grant_info = pairing_bootstrap_info(&invite_id, "grant");
    let sealed_grant =
        crypto::seal_bootstrap(&joining.x25519_pub, &grant_info, &grant_bytes).unwrap();
    let opened_grant = crypto::open_bootstrap(&joining, &grant_info, &sealed_grant).unwrap();
    let decoded_grant: PairingRosterPayload = postcard::from_bytes(&opened_grant).unwrap();
    let verified = verify_persisted_roster_entries(decoded_grant.roster_chain).unwrap();
    assert!(verified.is_active(&joining.signing_pub));
    assert_eq!(verified.entry.admin_id, admin.signing_pub);
}

#[test]
fn safe_default_file_name_removes_paths_and_unsafe_chars() {
    assert_eq!(safe_default_file_name(r"..\..\secret?.txt"), "secret_.txt");
    assert_eq!(safe_default_file_name("bad:name.txt"), "bad_name.txt");
    assert_eq!(safe_default_file_name(""), "fwoosh-file");
    assert_eq!(safe_default_file_name("."), "fwoosh-file");
}

#[test]
fn file_finish_frame_carries_stream_checksum() {
    let sha256 = [0xA5; 32];
    let bytes = postcard::to_allocvec(&FileFrame::Finish { sha256 }).unwrap();
    let frame: FileFrame = postcard::from_bytes(&bytes).unwrap();

    assert!(matches!(frame, FileFrame::Finish { sha256: actual } if actual == sha256));
}

#[test]
fn legacy_settings_default_transfer_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        r#"{"device_label":"Desk","stun_servers":["stun:example.com:3478"]}"#,
    )
    .unwrap();

    let settings = load_settings(&path);
    assert_eq!(settings.device_label.as_deref(), Some("Desk"));
    assert_eq!(settings.stun_servers, vec!["stun:example.com:3478"]);
    assert_eq!(
        settings.transfer_timeout_minutes,
        DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES
    );
}

#[test]
fn transfer_timeout_bounds_are_validated() {
    assert!(normalize_transfer_timeout_minutes(0).is_err());
    assert!(normalize_transfer_timeout_minutes(DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES).is_ok());
    assert!(normalize_transfer_timeout_minutes(MAX_FILE_TRANSFER_TIMEOUT_MINUTES).is_ok());
    assert!(normalize_transfer_timeout_minutes(MAX_FILE_TRANSFER_TIMEOUT_MINUTES + 1).is_err());
}

#[tokio::test]
async fn stale_transfer_timeout_token_does_not_cleanup() {
    let store = HistoryStore::open(Path::new(":memory:"), &[7u8; 32]).unwrap();
    let state = Arc::new(AppState::new(DeviceKeypairs::generate(), store));
    let session_id = "0123456789abcdef0123456789abcdef";
    state.file_transfers.lock().await.insert(
        session_id.to_string(),
        TransferRecord::PendingIncoming(PendingIncomingTransfer {
            sender_id: crypto::Ed25519PubKey([1u8; 32]),
            file_name: "large.bin".to_string(),
            size: u64::from(u32::MAX) + 1,
            content_key: [3u8; 32],
            nonce_prefix: [4u8; FILE_NONCE_PREFIX_LEN],
            offer_sdp_json: "{}".to_string(),
            timeout_token: 100,
        }),
    );

    assert!(!cleanup_transfer_if_timeout_token(&state, session_id, 99).await);
    assert!(state.file_transfers.lock().await.contains_key(session_id));
    assert!(cleanup_transfer_if_timeout_token(&state, session_id, 100).await);
    assert!(!state.file_transfers.lock().await.contains_key(session_id));
}

#[tokio::test]
async fn terminal_transfer_state_can_only_be_claimed_once() {
    let store = HistoryStore::open(Path::new(":memory:"), &[8u8; 32]).unwrap();
    let state = Arc::new(AppState::new(DeviceKeypairs::generate(), store));
    let session_id = "11111111111111111111111111111111";
    state.file_transfers.lock().await.insert(
        session_id.to_string(),
        TransferRecord::PendingIncoming(PendingIncomingTransfer {
            sender_id: crypto::Ed25519PubKey([1u8; 32]),
            file_name: "complete.bin".to_string(),
            size: 1,
            content_key: [3u8; 32],
            nonce_prefix: [4u8; FILE_NONCE_PREFIX_LEN],
            offer_sdp_json: "{}".to_string(),
            timeout_token: 101,
        }),
    );

    assert!(take_transfer(&state, session_id).await.is_some());
    assert!(take_transfer(&state, session_id).await.is_none());
    assert!(!cleanup_transfer(&state, session_id).await);
}

#[tokio::test]
async fn completed_received_file_lookup_rejects_arbitrary_paths() {
    let store = HistoryStore::open(Path::new(":memory:"), &[9u8; 32]).unwrap();
    let state = Arc::new(AppState::new(DeviceKeypairs::generate(), store));
    let session_id = "22222222222222222222222222222222";
    let path = PathBuf::from("/tmp/received.txt");

    remember_completed_received_file(&state, session_id, path.clone()).await;

    assert_eq!(
        completed_received_file_path(&state, &path).await.unwrap(),
        path
    );
    assert!(
        completed_received_file_path(&state, Path::new("/tmp/not-received.txt"))
            .await
            .unwrap_err()
            .contains("not available")
    );
    assert!(
        completed_received_file_path(&state, Path::new("../../secret"))
            .await
            .unwrap_err()
            .contains("not available")
    );
}

#[test]
fn receive_destination_rejects_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    let final_path = dir.path().join("incoming.txt");
    std::fs::write(&final_path, b"existing").unwrap();

    assert!(ensure_receive_destination_available(&final_path)
        .unwrap_err()
        .contains("already exists"));
    assert!(ensure_receive_destination_available(&dir.path().join("new.txt")).is_ok());
}

#[tokio::test]
async fn finalization_refuses_to_overwrite_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let part_path = dir.path().join("incoming.txt.fwoosh-part");
    let final_path = dir.path().join("incoming.txt");
    tokio::fs::write(&part_path, b"new").await.unwrap();
    tokio::fs::write(&final_path, b"old").await.unwrap();

    assert!(finalize_received_file_no_overwrite(&part_path, &final_path)
        .await
        .unwrap_err()
        .contains("already exists"));
    assert_eq!(tokio::fs::read(&final_path).await.unwrap(), b"old");
    assert_eq!(tokio::fs::read(&part_path).await.unwrap(), b"new");
}

#[test]
fn persisted_roster_chain_must_verify_from_genesis() {
    let admin = DeviceKeypairs::generate();
    let bob = DeviceKeypairs::generate();
    let genesis = roster::build_genesis(&admin, "admin", "topic");
    let signed0 = roster::sign_and_chain(&admin, genesis, None).unwrap();
    let verified0 = VerifiedRoster::verify_first(signed0.clone()).unwrap();
    let unsigned1 = roster::build_add_device(&verified0.entry, identity(&bob, "bob"));
    let signed1 = roster::sign_and_chain(&admin, unsigned1, Some(&verified0.entry)).unwrap();

    let chain = PersistedRosterChain {
        version: 2,
        entries: vec![signed0, signed1.clone()],
    };
    let bytes = postcard::to_allocvec(&chain).unwrap();
    let loaded = verify_persisted_roster_entries(
        decode_persisted_roster_entries(&bytes).expect("chain decodes"),
    )
    .unwrap();
    assert_eq!(loaded.epoch(), 1);

    let lone_non_genesis = postcard::to_allocvec(&signed1).unwrap();
    let entries = decode_persisted_roster_entries(&lone_non_genesis).unwrap();
    assert!(verify_persisted_roster_entries(entries).is_err());
}

#[test]
fn legacy_genesis_roster_still_loads() {
    let admin = DeviceKeypairs::generate();
    let genesis = roster::build_genesis(&admin, "admin", "topic");
    let signed0 = roster::sign_and_chain(&admin, genesis, None).unwrap();
    let bytes = postcard::to_allocvec(&signed0).unwrap();

    let loaded = verify_persisted_roster_entries(
        decode_persisted_roster_entries(&bytes).expect("legacy entry decodes"),
    )
    .unwrap();
    assert_eq!(loaded.epoch(), 0);
}

#[test]
fn legacy_roster_migrates_into_default_sync_group() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("roster.bin");
    let groups_dir = dir.path().join("groups");
    let admin = DeviceKeypairs::generate();
    let genesis = roster::build_genesis(&admin, "admin", "legacy-topic");
    let signed = roster::sign_and_chain(&admin, genesis, None).unwrap();
    std::fs::write(&legacy_path, postcard::to_allocvec(&signed).unwrap()).unwrap();

    let mut settings = AppSettings::default();
    let (path, roster) = prepare_sync_groups(&mut settings, &groups_dir, &legacy_path)
        .unwrap()
        .expect("legacy roster creates a group");

    assert_eq!(settings.sync_groups.len(), 1);
    assert_eq!(settings.sync_groups[0].name, "My devices");
    assert_eq!(
        settings.active_sync_group_id.as_deref(),
        Some(settings.sync_groups[0].id.as_str())
    );
    assert!(path.starts_with(&groups_dir));
    assert_eq!(roster.unwrap().topic(), "legacy-topic");
    assert!(load_persisted_roster(&path).is_some());
}
