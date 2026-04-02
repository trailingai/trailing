use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use uuid::Uuid;

use super::{
    ActionEntry, GENESIS_HASH, IntegrityViolation, LEDGER_CHECKPOINT_INTERVAL,
    SCHEMA_VERSION_IMMUTABLE_LEDGER, SCHEMA_VERSION_LEGACY, StorageError,
    calculate_checkpoint_hash, connection_path, initialize_immutable_schema,
    initialize_legacy_schema, load_latest_hash, schema_user_version, set_schema_user_version,
    verify_chain, write_root_anchor,
};

pub type Result<T> = super::Result<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDirection {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOptions {
    pub apply: bool,
    pub direction: MigrationDirection,
    pub verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationProgress {
    pub phase: String,
    pub completed: i64,
    pub total: i64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationSnapshot {
    pub mode: String,
    pub user_version: i64,
    pub action_rows: i64,
    pub checkpoint_rows: i64,
    pub root_anchor_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationVerification {
    pub verified: bool,
    pub violation_count: usize,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationOutcome {
    pub dry_run: bool,
    pub direction: MigrationDirection,
    pub before: MigrationSnapshot,
    pub after: MigrationSnapshot,
    pub verification: Option<MigrationVerification>,
}

pub fn execute<F>(
    db_path: &Path,
    options: &MigrationOptions,
    mut progress: F,
) -> Result<MigrationOutcome>
where
    F: FnMut(MigrationProgress),
{
    progress(MigrationProgress {
        phase: "inspect".to_string(),
        completed: 0,
        total: 1,
        message: format!("Inspecting {}", db_path.display()),
    });

    let conn = Connection::open(db_path)?;
    let before = inspect(&conn)?;
    let planned_after = preview_after(&before, options.direction);

    if !options.apply {
        progress(MigrationProgress {
            phase: "inspect".to_string(),
            completed: 1,
            total: 1,
            message: "Dry run complete".to_string(),
        });
        return Ok(MigrationOutcome {
            dry_run: true,
            direction: options.direction,
            before,
            after: planned_after,
            verification: None,
        });
    }

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let execution = (|| {
        match options.direction {
            MigrationDirection::Apply => apply_migration(&conn, &mut progress)?,
            MigrationDirection::Rollback => rollback_migration(&conn, &mut progress)?,
        }

        let verification = if options.verify {
            progress(MigrationProgress {
                phase: "verify".to_string(),
                completed: 0,
                total: 1,
                message: "Verifying migrated ledger".to_string(),
            });
            let violations = verify_chain(&conn, None, None)?;
            let verification = summarize_verification(&violations);
            if !verification.verified {
                return Err(StorageError::InvalidInput(format!(
                    "migration verification failed with {} violations",
                    verification.violation_count
                )));
            }
            progress(MigrationProgress {
                phase: "verify".to_string(),
                completed: 1,
                total: 1,
                message: "Verification passed".to_string(),
            });
            Some(verification)
        } else {
            None
        };

        conn.execute_batch("COMMIT")?;
        let after = inspect(&conn)?;

        Ok(MigrationOutcome {
            dry_run: false,
            direction: options.direction,
            before,
            after,
            verification,
        })
    })();

    if execution.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }

    execution
}

fn apply_migration<F>(conn: &Connection, progress: &mut F) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    progress(MigrationProgress {
        phase: "schema".to_string(),
        completed: 0,
        total: 1,
        message: "Switching database to immutable checkpoint schema".to_string(),
    });
    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_delete;
        DROP TABLE IF EXISTS ledger_checkpoints;
        ",
    )?;
    initialize_immutable_schema(conn)?;
    set_schema_user_version(conn, SCHEMA_VERSION_IMMUTABLE_LEDGER)?;
    progress(MigrationProgress {
        phase: "schema".to_string(),
        completed: 1,
        total: 1,
        message: "Immutable schema ready".to_string(),
    });

    let action_rows = count_rows(conn, "action_log")?;
    progress(MigrationProgress {
        phase: "backfill".to_string(),
        completed: 0,
        total: action_rows,
        message: "Backfilling ledger checkpoints".to_string(),
    });
    let inserted = backfill_checkpoints(conn, action_rows, progress)?;
    progress(MigrationProgress {
        phase: "backfill".to_string(),
        completed: inserted,
        total: action_rows,
        message: format!("Backfilled {inserted} checkpoint rows"),
    });

    if let Some(path) = connection_path(conn)? {
        write_root_anchor(&path, None)?;
    }

    Ok(())
}

fn rollback_migration<F>(conn: &Connection, progress: &mut F) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    progress(MigrationProgress {
        phase: "schema".to_string(),
        completed: 0,
        total: 1,
        message: "Restoring legacy action_log schema".to_string(),
    });
    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_delete;
        DROP TABLE IF EXISTS ledger_checkpoints;
        ",
    )?;
    initialize_legacy_schema(conn)?;
    set_schema_user_version(conn, SCHEMA_VERSION_LEGACY)?;
    write_root_anchor_for_current_ledger(conn)?;
    progress(MigrationProgress {
        phase: "schema".to_string(),
        completed: 1,
        total: 1,
        message: "Legacy schema restored".to_string(),
    });

    Ok(())
}

fn backfill_checkpoints<F>(conn: &Connection, total_rows: i64, progress: &mut F) -> Result<i64>
where
    F: FnMut(MigrationProgress),
{
    let mut statement = conn.prepare(
        "SELECT sequence, id, entry_hash
         FROM action_log
         ORDER BY sequence ASC",
    )?;
    let mut rows = statement.query([])?;

    let mut previous_checkpoint_hash = GENESIS_HASH.to_string();
    let mut last_checkpoint_end = 0i64;
    let mut inserted = 0i64;
    let report_every = 250i64;

    while let Some(row) = rows.next()? {
        let sequence = row.get::<_, i64>(0)?;
        let entry_id = row.get::<_, String>(1)?;
        let entry_hash = row.get::<_, String>(2)?;

        if sequence - last_checkpoint_end < LEDGER_CHECKPOINT_INTERVAL {
            continue;
        }

        let start_sequence = last_checkpoint_end + 1;
        let entry_count = sequence - start_sequence + 1;
        let checkpoint_hash = calculate_checkpoint_hash(
            start_sequence,
            sequence,
            entry_count,
            &entry_id,
            &entry_hash,
            &previous_checkpoint_hash,
        );
        conn.execute(
            "INSERT INTO ledger_checkpoints (
                checkpoint_id,
                checkpointed_at,
                start_sequence,
                end_sequence,
                entry_count,
                last_entry_id,
                last_entry_hash,
                previous_checkpoint_hash,
                checkpoint_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                Uuid::new_v4().to_string(),
                ActionEntry::canonical_timestamp(&super::current_time()),
                start_sequence,
                sequence,
                entry_count,
                entry_id,
                entry_hash,
                previous_checkpoint_hash,
                checkpoint_hash.clone(),
            ],
        )?;

        inserted += 1;
        last_checkpoint_end = sequence;
        previous_checkpoint_hash = checkpoint_hash;

        if inserted % report_every == 0 || inserted == total_rows {
            progress(MigrationProgress {
                phase: "backfill".to_string(),
                completed: inserted,
                total: total_rows,
                message: format!("Processed {inserted} of {total_rows} action rows"),
            });
        }
    }

    Ok(inserted)
}

fn inspect(conn: &Connection) -> Result<MigrationSnapshot> {
    let action_rows = count_rows(conn, "action_log")?;
    let checkpoint_rows = count_rows(conn, "ledger_checkpoints")?;
    let root_anchor_present = connection_path(conn)?
        .map(|path| path.exists())
        .unwrap_or(false);
    let user_version = schema_user_version(conn)?;
    let mode = if checkpoint_rows > 0 || table_exists(conn, "ledger_checkpoints")? {
        "immutable"
    } else if table_exists(conn, "action_log")? {
        "legacy"
    } else {
        "empty"
    };

    Ok(MigrationSnapshot {
        mode: mode.to_string(),
        user_version,
        action_rows,
        checkpoint_rows,
        root_anchor_present,
    })
}

fn preview_after(before: &MigrationSnapshot, direction: MigrationDirection) -> MigrationSnapshot {
    match direction {
        MigrationDirection::Apply => MigrationSnapshot {
            mode: "immutable".to_string(),
            user_version: SCHEMA_VERSION_IMMUTABLE_LEDGER,
            action_rows: before.action_rows,
            checkpoint_rows: expected_checkpoint_rows(before.action_rows),
            root_anchor_present: false,
        },
        MigrationDirection::Rollback => MigrationSnapshot {
            mode: "legacy".to_string(),
            user_version: SCHEMA_VERSION_LEGACY,
            action_rows: before.action_rows,
            checkpoint_rows: 0,
            root_anchor_present: before.action_rows > 0,
        },
    }
}

fn expected_checkpoint_rows(action_rows: i64) -> i64 {
    if action_rows == 0 {
        0
    } else {
        (action_rows + LEDGER_CHECKPOINT_INTERVAL - 1) / LEDGER_CHECKPOINT_INTERVAL
    }
}

fn summarize_verification(violations: &[IntegrityViolation]) -> MigrationVerification {
    MigrationVerification {
        verified: violations.is_empty(),
        violation_count: violations.len(),
        reasons: violations
            .iter()
            .map(|violation| violation.reason.clone())
            .collect(),
    }
}

fn count_rows(conn: &Connection, table_name: &str) -> Result<i64> {
    if !table_exists(conn, table_name)? {
        return Ok(0);
    }

    conn.query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
        row.get(0)
    })
    .map_err(StorageError::from)
}

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
        params![table_name],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|value| value.is_some())
    .map_err(StorageError::from)
}

fn write_root_anchor_for_current_ledger(conn: &Connection) -> Result<()> {
    if let Some(path) = connection_path(conn)? {
        write_root_anchor(&path, load_latest_hash(conn)?.as_deref())?;
    }

    Ok(())
}
