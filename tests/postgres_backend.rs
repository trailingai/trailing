use std::sync::{Mutex, MutexGuard, OnceLock};

use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use tokio_postgres::NoTls;

use trailing::{
    checkpoint::{CheckpointSigner, SignatureAlgorithm},
    log::{ActionType, GENESIS_HASH},
    storage::{
        DeduplicationOutcome, ExternalAnchorInput, LedgerBackend, MERKLE_BATCH_SIZE,
        PostgresStorage, SqliteStorage, Storage, StorageScope, verify_inclusion_proof,
    },
};

fn append_seed_entries<B: LedgerBackend>(storage: &B, count: usize) {
    let base_time = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();

    for index in 0..count {
        storage
            .append_action_at(
                base_time + Duration::seconds(index as i64),
                format!("agent-{}", index % 3),
                "worker",
                format!("session-{}", index % 5),
                match index % 3 {
                    0 => ActionType::ToolCall,
                    1 => ActionType::Decision,
                    _ => ActionType::PolicyCheck,
                },
                json!({ "index": index }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append seed entry");
    }
}

fn get_postgres_dsn() -> Option<String> {
    std::env::var("POSTGRES_DSN")
        .ok()
        .or_else(|| std::env::var("TRAILING_TEST_POSTGRES_URL").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

struct PostgresTestContext {
    database_url: String,
    _guard: MutexGuard<'static, ()>,
}

impl PostgresTestContext {
    fn new(test_name: &str) -> Option<Self> {
        let Some(database_url) = get_postgres_dsn() else {
            eprintln!("skipping {test_name}: POSTGRES_DSN not set");
            return None;
        };

        let guard = postgres_test_lock().lock().expect("postgres test lock");
        reset_postgres_database(&database_url);

        Some(Self {
            database_url,
            _guard: guard,
        })
    }

    fn storage(&self) -> Storage {
        Storage::open(&self.database_url).expect("postgres storage")
    }

    fn backend(&self) -> PostgresStorage {
        PostgresStorage::open(&self.database_url).expect("postgres storage")
    }

    fn database_url(&self) -> &str {
        &self.database_url
    }
}

impl Drop for PostgresTestContext {
    fn drop(&mut self) {
        reset_postgres_database(&self.database_url);
    }
}

#[test]
fn sqlite_backend_materializes_merkle_batches_and_checkpoints() {
    let storage = SqliteStorage::open_in_memory().expect("sqlite storage");
    append_seed_entries(&storage, MERKLE_BATCH_SIZE as usize + 6);

    let batches = storage.merkle_batches().expect("sqlite merkle batches");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].leaf_count, MERKLE_BATCH_SIZE);
    assert_eq!(batches[0].start_sequence, 1);
    assert_eq!(batches[0].end_sequence, MERKLE_BATCH_SIZE);

    let checkpoint = storage.create_checkpoint().expect("sqlite checkpoint");
    let latest = storage
        .latest_checkpoint()
        .expect("sqlite latest checkpoint")
        .expect("sqlite checkpoint present");

    assert_eq!(checkpoint, latest);
    assert_eq!(checkpoint.sequence, MERKLE_BATCH_SIZE + 6);
    assert_eq!(
        checkpoint.entry_hash,
        storage
            .entries()
            .expect("sqlite entries")
            .last()
            .expect("sqlite latest entry")
            .entry_hash
    );
    assert!(!checkpoint.merkle_root.is_empty());
}

#[test]
fn postgres_backend_matches_immutable_semantics_when_configured() {
    let Some(context) =
        PostgresTestContext::new("postgres_backend_matches_immutable_semantics_when_configured")
    else {
        return;
    };

    let storage = context.backend();

    append_seed_entries(&storage, MERKLE_BATCH_SIZE as usize + 1);

    let violations = storage
        .verify_chain(None, None)
        .expect("postgres verify chain");
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );

    let batches = storage.merkle_batches().expect("postgres merkle batches");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].leaf_count, MERKLE_BATCH_SIZE);

    let checkpoint = storage.create_checkpoint().expect("postgres checkpoint");
    assert_eq!(checkpoint.sequence, MERKLE_BATCH_SIZE + 1);
    assert_eq!(
        storage
            .latest_checkpoint()
            .expect("postgres latest checkpoint"),
        Some(checkpoint.clone())
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("postgres test runtime");
    let error = runtime
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(context.database_url(), NoTls)
                .await
                .expect("connect postgres");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
                .execute(
                    "UPDATE action_log SET outcome = 'tampered' WHERE sequence = 1",
                    &[],
                )
                .await
                .expect_err("postgres action_log update should be blocked")
        })
        .to_string();

    assert!(error.contains("append-only"));
}

#[test]
fn postgres_backend_appends_queries_and_scoped_verification_when_configured() {
    let Some(context) = PostgresTestContext::new(
        "postgres_backend_appends_queries_and_scoped_verification_when_configured",
    ) else {
        return;
    };

    let storage = context.storage();

    let timestamp = Utc.with_ymd_and_hms(2026, 3, 31, 9, 0, 0).unwrap();
    let first = storage
        .append_action_at_for_tenant(
            "org-1",
            "project-a",
            timestamp,
            "agent-a",
            "worker",
            "session-a",
            ActionType::ToolCall,
            json!({ "project": "a" }),
            json!({}),
            "ok",
        )
        .expect("append project a entry");
    let second = storage
        .append_action_at_for_tenant(
            "org-1",
            "project-a",
            timestamp + Duration::seconds(1),
            "agent-a",
            "worker",
            "session-a",
            ActionType::Decision,
            json!({ "project": "a", "index": 1 }),
            json!({}),
            "ok",
        )
        .expect("append second project a entry");
    let third = storage
        .append_action_at_for_tenant(
            "org-1",
            "project-b",
            timestamp + Duration::seconds(2),
            "agent-b",
            "worker",
            "session-b",
            ActionType::Decision,
            json!({ "project": "b" }),
            json!({}),
            "ok",
        )
        .expect("append project b entry");

    let all_entries = storage.entries().expect("postgres entries");
    let scope = StorageScope {
        org_id: "org-1".to_string(),
        project_id: "project-a".to_string(),
    };
    let scoped_entries = storage
        .entries_for_scope(&scope)
        .expect("postgres scoped entries");
    let org_entries = storage
        .entries_for_org(Some("org-1"))
        .expect("postgres org entries");
    let violations = storage
        .verify_chain_for_scope(&scope)
        .expect("postgres scoped verify");

    assert_eq!(storage.backend_name(), "postgres");
    assert_eq!(all_entries.len(), 3);
    assert_eq!(all_entries[0].id, first.id);
    assert_eq!(all_entries[1].id, second.id);
    assert_eq!(all_entries[2].id, third.id);
    assert_eq!(org_entries.len(), 3);
    assert_eq!(scoped_entries.len(), 2);
    assert_eq!(scoped_entries[0].payload["project"], json!("a"));
    assert_eq!(scoped_entries[0].previous_hash, GENESIS_HASH);
    assert_eq!(
        scoped_entries[1].previous_hash,
        scoped_entries[0].entry_hash
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );
}

#[test]
fn postgres_backend_deduplicates_actions_when_configured() {
    let Some(context) =
        PostgresTestContext::new("postgres_backend_deduplicates_actions_when_configured")
    else {
        return;
    };

    let storage = context.storage();
    let timestamp = Utc.with_ymd_and_hms(2026, 3, 31, 10, 0, 0).unwrap();
    let first = storage
        .append_action_with_dedup_at_for_org_detailed(
            Some("org-dedup"),
            "dedup-key-1",
            timestamp,
            "agent-1",
            "worker",
            "session-1",
            ActionType::ToolCall,
            json!({ "request": 1 }),
            json!({ "source": "integration-test" }),
            "ok",
        )
        .expect("insert deduplicated action");
    let duplicate = storage
        .append_action_with_dedup_at_for_org_detailed(
            Some("org-dedup"),
            "dedup-key-1",
            timestamp + Duration::seconds(1),
            "agent-2",
            "worker",
            "session-2",
            ActionType::Decision,
            json!({ "request": 2 }),
            json!({ "source": "integration-test" }),
            "ignored",
        )
        .expect("detect duplicate action");

    let inserted_entry_id = match first {
        DeduplicationOutcome::Inserted(entry) => {
            assert_eq!(entry.payload["request"], json!(1));
            entry.id.to_string()
        }
        DeduplicationOutcome::Duplicate { .. } => panic!("expected inserted entry"),
    };

    match duplicate {
        DeduplicationOutcome::Inserted(_) => panic!("expected duplicate response"),
        DeduplicationOutcome::Duplicate { entry_id } => {
            assert_eq!(entry_id.as_deref(), Some(inserted_entry_id.as_str()));
        }
    }

    let entries = storage
        .entries_for_org(Some("org-dedup"))
        .expect("deduplicated entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id.to_string(), inserted_entry_id);
}

#[test]
fn postgres_backend_stores_auth_audit_entries_when_configured() {
    let Some(context) =
        PostgresTestContext::new("postgres_backend_stores_auth_audit_entries_when_configured")
    else {
        return;
    };

    let storage = context.backend();
    let created = storage
        .create_api_key("org-auth", "primary")
        .expect("create api key");
    let authenticated = storage
        .authenticate_api_key(&created.key)
        .expect("authenticate api key")
        .expect("authenticated api key");
    assert_eq!(authenticated.id, created.id);
    assert!(storage.revoke_api_key(&created.id).expect("revoke api key"));

    let entries = storage.auth_audit_entries().expect("auth audit entries");

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].subject_id, created.id);
    assert_eq!(entries[0].previous_hash, GENESIS_HASH);
    assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
    assert_eq!(entries[2].previous_hash, entries[1].entry_hash);
    assert_eq!(entries[1].actor_id.as_deref(), Some(created.id.as_str()));
    assert_eq!(entries[1].outcome, "authenticated");
    assert_eq!(entries[2].outcome, "revoked");
}

#[test]
fn postgres_backend_creates_and_verifies_checkpoints_when_configured() {
    let Some(context) = PostgresTestContext::new(
        "postgres_backend_creates_and_verifies_checkpoints_when_configured",
    ) else {
        return;
    };

    let storage = context.storage();
    let timestamp = Utc.with_ymd_and_hms(2026, 3, 31, 12, 0, 0).unwrap();

    for index in 0..3 {
        storage
            .append_action_at(
                timestamp + Duration::seconds(index as i64),
                format!("agent-{index}"),
                "worker",
                "session-checkpoint",
                ActionType::ToolCall,
                json!({ "index": index }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append checkpoint seed entry");
    }

    let ledger_checkpoint = storage
        .create_checkpoint()
        .expect("create ledger checkpoint");
    assert_eq!(
        storage
            .latest_checkpoint()
            .expect("latest ledger checkpoint"),
        Some(ledger_checkpoint.clone())
    );

    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::Ed25519,
        "audit-key-ed25519",
        Some("primary".to_string()),
        &[5u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 31, 11, 0, 0).unwrap(),
    )
    .expect("create signer");

    let signed_checkpoint = storage
        .create_signed_checkpoint(
            &signer,
            &[ExternalAnchorInput {
                provider: "rfc3161".to_string(),
                reference: "tsa://receipt-123".to_string(),
                anchored_at: Some("2026-03-31T12:00:05Z".to_string()),
                metadata: json!({ "receipt": "abc123" }),
            }],
        )
        .expect("create signed checkpoint");
    let verification = storage
        .verify_signed_checkpoint(&signed_checkpoint.checkpoint_id)
        .expect("verify signed checkpoint")
        .expect("signed checkpoint exists");

    assert_eq!(ledger_checkpoint.sequence, 3);
    assert_eq!(signed_checkpoint.sequence, ledger_checkpoint.sequence);
    assert_eq!(signed_checkpoint.key.key_id, "audit-key-ed25519");
    assert_eq!(signed_checkpoint.anchors.len(), 1);
    assert!(verification.verification.signature_valid);
    assert!(verification.anchor_hashes_valid);
    assert!(verification.verified);
}

#[test]
fn postgres_backend_generates_merkle_proofs_when_configured() {
    let Some(context) =
        PostgresTestContext::new("postgres_backend_generates_merkle_proofs_when_configured")
    else {
        return;
    };

    let storage = context.backend();
    let scope = StorageScope {
        org_id: "org-merkle".to_string(),
        project_id: "project-a".to_string(),
    };
    let timestamp = Utc.with_ymd_and_hms(2026, 3, 31, 13, 0, 0).unwrap();

    for index in 0..(MERKLE_BATCH_SIZE as usize + 7) {
        storage
            .append_action_at_for_tenant(
                &scope.org_id,
                &scope.project_id,
                timestamp + Duration::seconds(index as i64),
                format!("agent-{}", index % 4),
                "worker",
                "session-merkle",
                ActionType::ToolCall,
                json!({ "index": index, "value": format!("payload-{index}") }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append merkle entry");
    }

    let batches = storage.merkle_batches().expect("load merkle batches");
    let target = storage
        .entries_for_scope(&scope)
        .expect("load scoped entries")[MERKLE_BATCH_SIZE as usize + 2]
        .clone();
    let proof = storage
        .merkle_proof(target.id)
        .expect("load merkle proof")
        .expect("expected proof for stored entry");

    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].leaf_count, MERKLE_BATCH_SIZE);
    assert_eq!(batches[1].leaf_count, 7);
    assert_eq!(proof.batch_index, 1);
    assert_eq!(proof.batch_root, batches[1].root_hash);
    assert!(verify_inclusion_proof(&target, &proof));

    let mut tampered = target.clone();
    tampered.payload = json!({ "index": 130, "value": "tampered" });
    assert!(!verify_inclusion_proof(&tampered, &proof));
}

fn postgres_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn reset_postgres_database(database_url: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("postgres cleanup runtime");
    runtime.block_on(async {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .expect("connect postgres for cleanup");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(
                "TRUNCATE TABLE
                    action_log,
                    chain_integrity_checks,
                    ledger_root_anchors,
                    ledger_checkpoints,
                    merkle_batches,
                    ingest_dedup,
                    api_keys,
                    checkpoint_signing_keys,
                    signed_checkpoints,
                    checkpoint_anchors,
                    legal_holds,
                    legal_hold_events,
                    purge_events,
                    credentials,
                    users,
                    auth_sessions,
                    human_users,
                    org_mfa_policies,
                    auth_challenges,
                    human_recovery_codes
                 RESTART IDENTITY CASCADE;
                 UPDATE app_settings SET admin_key_id = NULL WHERE id = 1;
                 UPDATE storage_control
                 SET allow_purge = FALSE, min_retention_days = 0, purge_through_sequence = NULL
                 WHERE id = 1;",
            )
            .await
            .expect("reset postgres test database");
    });
}
