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
fn legacy_settings_keep_the_first_group_as_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let first = "11111111111111111111111111111111";
    let second = "22222222222222222222222222222222";
    std::fs::write(
        &path,
        format!(
            r#"{{"device_label":"Desk","stun_servers":["stun:example.com:3478"],"sync_groups":[{{"id":"{first}","name":"My devices"}},{{"id":"{second}","name":"Friends"}}],"active_sync_group_id":"{second}"}}"#
        ),
    )
    .unwrap();

    let settings = load_settings(&path);
    assert_eq!(settings.active_sync_group_id.as_deref(), Some(second));
    assert_eq!(settings.default_sync_group_id.as_deref(), Some(first));
}

#[test]
fn startup_selects_the_configured_default_group() {
    let dir = tempfile::tempdir().unwrap();
    let groups_dir = dir.path().join("groups");
    let legacy_path = dir.path().join("roster.bin");
    let first = "11111111111111111111111111111111".to_string();
    let second = "22222222222222222222222222222222".to_string();
    let mut settings = AppSettings {
        sync_groups: vec![
            SyncGroupConfig {
                id: first.clone(),
                name: "My devices".to_string(),
            },
            SyncGroupConfig {
                id: second.clone(),
                name: "Friends".to_string(),
            },
        ],
        active_sync_group_id: Some(second),
        default_sync_group_id: Some(first.clone()),
        ..AppSettings::default()
    };

    let (selected_path, roster) = prepare_sync_groups(&mut settings, &groups_dir, &legacy_path)
        .unwrap()
        .expect("configured groups select one at startup");

    assert!(roster.is_none());
    assert_eq!(
        settings.active_sync_group_id.as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        settings.default_sync_group_id.as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        selected_path.file_name().and_then(|name| name.to_str()),
        Some("11111111111111111111111111111111.bin")
    );
}

#[tokio::test]
async fn first_created_group_becomes_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::new(
        DeviceKeypairs::generate(),
        HistoryStore::open(Path::new(":memory:"), &[12u8; 32]).unwrap(),
    ));
    *state.groups_dir.lock().await = Some(dir.path().join("groups"));
    std::fs::create_dir_all(state.groups_dir.lock().await.as_ref().unwrap()).unwrap();

    let id = ensure_active_sync_group(&state, "My devices")
        .await
        .unwrap();
    let settings = state.settings.lock().await;
    assert_eq!(settings.active_sync_group_id.as_deref(), Some(id.as_str()));
    assert_eq!(settings.default_sync_group_id.as_deref(), Some(id.as_str()));
}

#[test]
fn adding_another_group_preserves_the_existing_default() {
    let first = "11111111111111111111111111111111".to_string();
    let second = "22222222222222222222222222222222".to_string();
    let mut settings = AppSettings {
        sync_groups: vec![SyncGroupConfig {
            id: first.clone(),
            name: "My devices".to_string(),
        }],
        active_sync_group_id: Some(first.clone()),
        default_sync_group_id: Some(first.clone()),
        ..AppSettings::default()
    };

    let (previous_active, previous_default) =
        sync_groups::add_sync_group_config(&mut settings, second.clone(), "Friends".to_string())
            .unwrap();

    assert_eq!(previous_active.as_deref(), Some(first.as_str()));
    assert_eq!(previous_default.as_deref(), Some(first.as_str()));
    assert_eq!(
        settings.default_sync_group_id.as_deref(),
        Some(first.as_str())
    );
    assert!(settings.sync_groups.iter().any(|group| group.id == second));
}

#[test]
fn disconnected_group_cannot_become_default() {
    let error = sync_groups::ensure_group_can_be_default(None).unwrap_err();
    assert!(error.contains("connected, approved group"));
}

#[test]
fn destructive_group_action_rejects_a_stale_active_group() {
    let first = "11111111111111111111111111111111".to_string();
    let second = "22222222222222222222222222222222".to_string();
    let settings = AppSettings {
        active_sync_group_id: Some(second),
        ..AppSettings::default()
    };

    let error = sync_groups::ensure_expected_active_group(&settings, &first, "deleting the group")
        .unwrap_err();
    assert!(error.contains("active group changed"));
}

#[test]
fn removing_a_default_group_selects_a_safe_replacement() {
    let first = "11111111111111111111111111111111".to_string();
    let second = "22222222222222222222222222222222".to_string();
    let mut settings = AppSettings {
        sync_groups: vec![
            SyncGroupConfig {
                id: first.clone(),
                name: "My devices".to_string(),
            },
            SyncGroupConfig {
                id: second.clone(),
                name: "Friends".to_string(),
            },
        ],
        active_sync_group_id: Some(first.clone()),
        default_sync_group_id: Some(first.clone()),
        ..AppSettings::default()
    };

    let next = sync_groups::remove_group_from_settings(&mut settings, &first, None).unwrap();

    assert_eq!(next.as_deref(), Some(second.as_str()));
    assert_eq!(
        settings.default_sync_group_id.as_deref(),
        Some(second.as_str())
    );
}

#[test]
fn group_admin_cannot_leave_members_orphaned() {
    let admin = DeviceKeypairs::generate();
    let member = DeviceKeypairs::generate();
    let genesis = roster::sign_and_chain(
        &admin,
        roster::build_genesis(&admin, "Admin", "topic"),
        None,
    )
    .unwrap();
    let with_member = roster::sign_and_chain(
        &admin,
        roster::build_add_device(&genesis, identity(&member, "Member")),
        Some(&genesis),
    )
    .unwrap();
    let verified = VerifiedRoster::verify_first(genesis)
        .unwrap()
        .verify_next(with_member)
        .unwrap();

    assert!(
        sync_groups::ensure_group_can_be_left_locally(&admin.signing_pub, Some(&verified))
            .unwrap_err()
            .contains("cannot leave while other devices remain")
    );
    assert!(
        sync_groups::ensure_group_can_be_left_locally(&member.signing_pub, Some(&verified)).is_ok()
    );
    assert!(
        sync_groups::ensure_group_can_be_left_locally(&admin.signing_pub, None)
            .unwrap_err()
            .contains("verified membership could not be loaded")
    );
}

#[test]
fn group_removal_notice_is_private_and_victim_only() {
    let admin = DeviceKeypairs::generate();
    let victim = DeviceKeypairs::generate();
    let bystander = DeviceKeypairs::generate();
    let old_topic = "old-topic";
    let sealed = crypto::seal_clip(
        &admin,
        &[crypto::Recipient {
            id: victim.signing_pub.clone(),
            x25519: victim.x25519_pub.clone(),
        }],
        &encode_group_removal_notice(),
        old_topic,
        4,
        StorePolicy::Private,
        100,
    )
    .unwrap();

    assert_eq!(sealed.manifest.room_id, old_topic);
    assert_eq!(sealed.manifest.recipients.len(), 1);
    assert_eq!(
        sealed.manifest.recipients[0].recipient_id,
        victim.signing_pub
    );
    assert_eq!(sealed.manifest.store_policy, StorePolicy::Private);
    let opened = crypto::open_clip(&sealed.manifest, &sealed.chunks, &victim, 4, |id, _| {
        id == &admin.signing_pub
    })
    .unwrap();
    assert_eq!(opened.plaintext, encode_group_removal_notice());
    assert!(
        crypto::open_clip(&sealed.manifest, &sealed.chunks, &bystander, 4, |id, _| {
            id == &admin.signing_pub
        })
        .is_err()
    );
}

#[tokio::test]
async fn background_join_request_requires_switching_to_its_group() {
    let admin = DeviceKeypairs::generate();
    let joining = DeviceKeypairs::generate();
    let first = "11111111111111111111111111111111".to_string();
    let second = "22222222222222222222222222222222".to_string();
    let state = Arc::new(AppState::new(
        admin,
        HistoryStore::open(Path::new(":memory:"), &[13u8; 32]).unwrap(),
    ));
    {
        let mut settings = state.settings.lock().await;
        settings.sync_groups = vec![
            SyncGroupConfig {
                id: first.clone(),
                name: "My devices".to_string(),
            },
            SyncGroupConfig {
                id: second.clone(),
                name: "Friends".to_string(),
            },
        ];
        settings.active_sync_group_id = Some(first);
        settings.default_sync_group_id = Some(second.clone());
    }
    let invite_id = network::new_id();
    let secret = crate::pairing::random_secret();
    let request = crate::pairing::build_network_join_request(
        invite_id,
        identity(&joining, "Laptop"),
        &secret,
        now_unix(),
    );
    let pending = PendingJoinRecord {
        request_id: "request".to_string(),
        request_key: [7; 16],
        network_id: second.clone(),
        rendezvous_topic: "invite-topic".to_string(),
        request,
        received_at: now_unix(),
    };

    let error = pairing_commands::require_pending_group_active(&state, &pending, "approving")
        .await
        .unwrap_err();
    assert!(error.contains("Switch to the \"Friends\" group"));

    state.settings.lock().await.active_sync_group_id = Some(second);
    assert!(
        pairing_commands::require_pending_group_active(&state, &pending, "approving")
            .await
            .is_ok()
    );
}

#[test]
fn pairing_request_keys_are_deterministic_and_group_scoped() {
    let joining = DeviceKeypairs::generate();
    let first_invite = network::new_id();
    let second_invite = network::new_id();
    let secret = crate::pairing::random_secret();
    let first = crate::pairing::build_network_join_request(
        first_invite,
        identity(&joining, "Laptop"),
        &secret,
        123,
    );
    let second = crate::pairing::build_network_join_request(
        second_invite,
        identity(&joining, "Laptop"),
        &secret,
        123,
    );

    let first_key = pairing_commands::pairing_request_key("group-a", &first).unwrap();
    assert_eq!(
        first_key,
        pairing_commands::pairing_request_key("group-a", &first).unwrap()
    );
    assert_ne!(
        first_key,
        pairing_commands::pairing_request_key("group-b", &first).unwrap()
    );
    assert_ne!(
        first_key,
        pairing_commands::pairing_request_key("group-a", &second).unwrap()
    );
}

#[test]
fn pairing_request_decisions_survive_store_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");
    let key = [44u8; 16];
    let db_key = [15u8; 32];
    {
        let store = HistoryStore::open(&path, &db_key).unwrap();
        assert!(!store.has_seen_message(&key).unwrap());
        store.mark_seen_message(&key, 123).unwrap();
    }
    let reopened = HistoryStore::open(&path, &db_key).unwrap();
    assert!(reopened.has_seen_message(&key).unwrap());
}

#[tokio::test]
async fn strict_roster_persistence_is_retry_safe() {
    let dir = tempfile::tempdir().unwrap();
    let groups_dir = dir.path().join("groups");
    std::fs::create_dir_all(&groups_dir).unwrap();
    let state = Arc::new(AppState::new(
        DeviceKeypairs::generate(),
        HistoryStore::open(Path::new(":memory:"), &[16u8; 32]).unwrap(),
    ));
    *state.groups_dir.lock().await = Some(groups_dir.clone());
    let group_id = "33333333333333333333333333333333";
    let admin = DeviceKeypairs::generate();
    let joining = DeviceKeypairs::generate();
    let genesis = roster::sign_and_chain(
        &admin,
        roster::build_genesis(&admin, "Admin", "topic"),
        None,
    )
    .unwrap();
    sync_groups::persist_sync_group_roster_checked(&state, group_id, &genesis)
        .await
        .unwrap();
    let with_member = roster::sign_and_chain(
        &admin,
        roster::build_add_device(&genesis, identity(&joining, "Laptop")),
        Some(&genesis),
    )
    .unwrap();

    let path = sync_groups::persist_sync_group_roster_checked(&state, group_id, &with_member)
        .await
        .unwrap();
    sync_groups::persist_sync_group_roster_checked(&state, group_id, &with_member)
        .await
        .unwrap();

    let persisted = load_persisted_roster(&path).unwrap();
    assert_eq!(persisted.epoch(), 1);
    assert!(persisted.is_active(&joining.signing_pub));
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
            network_id: "group-a".to_string(),
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
            network_id: "group-a".to_string(),
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
    assert_eq!(
        settings.default_sync_group_id.as_deref(),
        Some(settings.sync_groups[0].id.as_str())
    );
    assert!(path.starts_with(&groups_dir));
    assert_eq!(roster.unwrap().topic(), "legacy-topic");
    assert!(load_persisted_roster(&path).is_some());
}
