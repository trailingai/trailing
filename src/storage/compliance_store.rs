use std::collections::{HashMap, HashSet};

use super::*;

impl Storage {
    pub fn purge_expired(&self, as_of: DateTime<Utc>) -> Result<usize> {
        match self {
            Self::Sqlite(storage) => storage.purge_expired(as_of),
            Self::Postgres(storage) => {
                let control = storage.control_settings()?;
                let policy = RetentionPolicy {
                    min_retention_days: control.min_retention_days,
                    legal_hold: false,
                };
                storage.purge_expired(&policy, as_of)
            }
        }
    }

    pub fn control_settings(&self) -> Result<StorageControl> {
        match self {
            Self::Sqlite(storage) => storage.control_settings(),
            Self::Postgres(storage) => storage.control_settings(),
        }
    }

    pub fn create_legal_hold(
        &self,
        org_id: Option<&str>,
        matter: &str,
        reason: &str,
        created_at: DateTime<Utc>,
    ) -> Result<LegalHoldRecord> {
        match self {
            Self::Sqlite(storage) => storage.create_legal_hold(org_id, matter, reason, created_at),
            Self::Postgres(storage) => {
                storage.create_legal_hold(org_id, matter, reason, created_at)
            }
        }
    }

    pub fn release_legal_hold(
        &self,
        hold_id: &str,
        released_at: DateTime<Utc>,
        release_reason: &str,
    ) -> Result<Option<LegalHoldRecord>> {
        match self {
            Self::Sqlite(storage) => {
                storage.release_legal_hold(hold_id, released_at, release_reason)
            }
            Self::Postgres(storage) => {
                storage.release_legal_hold(hold_id, released_at, release_reason)
            }
        }
    }

    pub fn legal_holds(&self, org_id: Option<&str>) -> Result<Vec<LegalHoldRecord>> {
        match self {
            Self::Sqlite(storage) => storage.legal_holds(org_id),
            Self::Postgres(storage) => storage.legal_holds(org_id),
        }
    }

    pub fn legal_hold_events(&self, hold_id: &str) -> Result<Vec<LegalHoldEvent>> {
        match self {
            Self::Sqlite(storage) => storage.legal_hold_events(hold_id),
            Self::Postgres(storage) => storage.legal_hold_events(hold_id),
        }
    }
}

impl SqliteStorage {
    pub fn purge_expired(&self, as_of: DateTime<Utc>) -> Result<usize> {
        purge_expired(&self.conn, as_of)
    }

    pub fn control_settings(&self) -> Result<StorageControl> {
        load_storage_control(&self.conn)
    }

    pub fn set_default_retention_days(&self, min_retention_days: i64) -> Result<()> {
        set_default_retention_days(&self.conn, min_retention_days)
    }

    pub fn set_org_retention_policy(
        &self,
        org_id: &str,
        min_retention_days: i64,
    ) -> Result<OrgRetentionPolicy> {
        set_org_retention_policy(&self.conn, org_id, min_retention_days)
    }

    pub fn retention_policy_for_org(&self, org_id: Option<&str>) -> Result<RetentionPolicy> {
        load_retention_policy_for_org(&self.conn, org_id)
    }

    pub fn create_legal_hold(
        &self,
        org_id: Option<&str>,
        matter: &str,
        reason: &str,
        created_at: DateTime<Utc>,
    ) -> Result<LegalHoldRecord> {
        create_legal_hold(&self.conn, org_id, matter, reason, created_at)
    }

    pub fn release_legal_hold(
        &self,
        hold_id: &str,
        released_at: DateTime<Utc>,
        release_reason: &str,
    ) -> Result<Option<LegalHoldRecord>> {
        release_legal_hold(&self.conn, hold_id, released_at, release_reason)
    }

    pub fn legal_holds(&self, org_id: Option<&str>) -> Result<Vec<LegalHoldRecord>> {
        load_legal_holds(&self.conn, org_id)
    }

    pub fn legal_hold_events(&self, hold_id: &str) -> Result<Vec<LegalHoldEvent>> {
        load_legal_hold_events(&self.conn, hold_id)
    }
}

pub fn purge_expired(conn: &Connection, as_of: DateTime<Utc>) -> Result<usize> {
    if is_immutable_schema(conn)? {
        return Err(StorageError::ImmutableLedger);
    }

    let default_retention_days = load_storage_control(conn)?.min_retention_days.max(0);
    let org_retention_days = load_org_retention_days(conn)?;
    let active_holds = load_active_hold_scope(conn)?;
    let entries = load_entries_for_range(conn, None, None, None, None)?;

    let mut delete_through_sequence = None;
    let mut delete_through_hash = None;
    let mut hold_blocked = false;

    for stored_entry in entries {
        let retention_days = stored_entry
            .org_id
            .as_deref()
            .and_then(|org_id| org_retention_days.get(org_id).copied())
            .unwrap_or(default_retention_days);
        let held = active_holds.global
            || stored_entry
                .org_id
                .as_deref()
                .is_some_and(|org_id| active_holds.org_ids.contains(org_id));
        if held {
            hold_blocked = delete_through_sequence.is_none();
            break;
        }

        let cutoff = as_of - chrono::Duration::days(retention_days.max(0));
        if stored_entry.entry.timestamp >= cutoff {
            break;
        }

        delete_through_sequence = Some(stored_entry.sequence);
        delete_through_hash = Some(stored_entry.entry.entry_hash.clone());
    }

    let Some(delete_through_sequence) = delete_through_sequence else {
        if hold_blocked {
            return Err(StorageError::LegalHoldActive);
        }
        return Ok(0);
    };
    let Some(delete_through_hash) = delete_through_hash else {
        return Err(StorageError::InvalidInput(
            "purge state missing terminal hash".to_string(),
        ));
    };

    let transaction = conn.unchecked_transaction()?;
    transaction.execute(
        "UPDATE storage_control
         SET allow_purge = 1,
             purge_through_sequence = ?1
         WHERE id = 1",
        params![delete_through_sequence],
    )?;
    let deleted_rows = transaction.execute(
        "DELETE FROM action_log WHERE sequence <= ?1",
        params![delete_through_sequence],
    )?;
    let remaining_rows = transaction.query_row("SELECT COUNT(*) FROM action_log", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let resume_previous_hash = (remaining_rows > 0).then(|| delete_through_hash.clone());
    transaction.execute(
        "INSERT INTO purge_events (
            id,
            purged_at,
            as_of,
            deleted_rows,
            through_sequence,
            through_entry_hash,
            resume_previous_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            Uuid::new_v4().to_string(),
            ActionEntry::canonical_timestamp(&current_time()),
            ActionEntry::canonical_timestamp(&as_of),
            deleted_rows as i64,
            delete_through_sequence,
            delete_through_hash,
            resume_previous_hash,
        ],
    )?;
    transaction.execute(
        "UPDATE storage_control
         SET allow_purge = 0,
             purge_through_sequence = NULL
         WHERE id = 1",
        [],
    )?;
    transaction.commit()?;

    Ok(deleted_rows)
}

fn load_storage_control(conn: &Connection) -> Result<StorageControl> {
    if table_has_column(conn, "storage_control", "allow_purge")? {
        conn.query_row(
            "SELECT allow_purge, min_retention_days FROM storage_control WHERE id = 1",
            [],
            |row| {
                Ok(StorageControl {
                    allow_purge: row.get::<_, i64>(0)? != 0,
                    min_retention_days: row.get(1)?,
                })
            },
        )
        .map_err(StorageError::from)
    } else {
        conn.query_row(
            "SELECT min_retention_days FROM storage_control WHERE id = 1",
            [],
            |row| {
                Ok(StorageControl {
                    allow_purge: false,
                    min_retention_days: row.get(0)?,
                })
            },
        )
        .map_err(StorageError::from)
    }
}

#[derive(Debug, Default)]
struct ActiveHoldScope {
    global: bool,
    org_ids: HashSet<String>,
}

fn set_default_retention_days(conn: &Connection, min_retention_days: i64) -> Result<()> {
    if min_retention_days < 0 {
        return Err(StorageError::InvalidInput(
            "retention days must not be negative".to_string(),
        ));
    }

    conn.execute(
        "UPDATE storage_control SET min_retention_days = ?1 WHERE id = 1",
        params![min_retention_days],
    )?;

    Ok(())
}

fn set_org_retention_policy(
    conn: &Connection,
    org_id: &str,
    min_retention_days: i64,
) -> Result<OrgRetentionPolicy> {
    let org_id = org_id.trim();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }
    if min_retention_days < 0 {
        return Err(StorageError::InvalidInput(
            "retention days must not be negative".to_string(),
        ));
    }

    let updated_at = ActionEntry::canonical_timestamp(&current_time());
    conn.execute(
        "INSERT INTO org_retention_policies (org_id, min_retention_days, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(org_id) DO UPDATE SET
            min_retention_days = excluded.min_retention_days,
            updated_at = excluded.updated_at",
        params![org_id, min_retention_days, updated_at],
    )?;

    Ok(OrgRetentionPolicy {
        org_id: org_id.to_string(),
        min_retention_days,
        updated_at,
    })
}

fn load_retention_policy_for_org(
    conn: &Connection,
    org_id: Option<&str>,
) -> Result<RetentionPolicy> {
    let default_retention_days = load_storage_control(conn)?.min_retention_days.max(0);
    let min_retention_days = match org_id {
        Some(org_id) => conn
            .query_row(
                "SELECT min_retention_days FROM org_retention_policies WHERE org_id = ?1",
                params![org_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(default_retention_days),
        None => default_retention_days,
    };

    Ok(RetentionPolicy {
        min_retention_days,
        legal_hold: has_active_legal_hold(conn, org_id)?,
    })
}

fn create_legal_hold(
    conn: &Connection,
    org_id: Option<&str>,
    matter: &str,
    reason: &str,
    created_at: DateTime<Utc>,
) -> Result<LegalHoldRecord> {
    let matter = matter.trim();
    let reason = reason.trim();
    if matter.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold matter must not be empty".to_string(),
        ));
    }
    if reason.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold reason must not be empty".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = ActionEntry::canonical_timestamp(&created_at);
    let org_id = org_id.map(str::trim).filter(|org_id| !org_id.is_empty());

    let transaction = conn.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO legal_holds (
            id,
            org_id,
            matter,
            reason,
            created_at,
            released_at,
            release_reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
        params![id, org_id, matter, reason, created_at],
    )?;
    insert_legal_hold_event(
        &transaction,
        &id,
        org_id,
        "created",
        &created_at,
        &format!("created legal hold for {matter}"),
    )?;
    transaction.commit()?;

    Ok(LegalHoldRecord {
        id,
        org_id: org_id.map(ToOwned::to_owned),
        matter: matter.to_string(),
        reason: reason.to_string(),
        created_at,
        released_at: None,
        release_reason: None,
    })
}

fn release_legal_hold(
    conn: &Connection,
    hold_id: &str,
    released_at: DateTime<Utc>,
    release_reason: &str,
) -> Result<Option<LegalHoldRecord>> {
    let release_reason = release_reason.trim();
    if release_reason.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold release reason must not be empty".to_string(),
        ));
    }

    let transaction = conn.unchecked_transaction()?;
    let Some(mut hold) = load_legal_hold(&transaction, hold_id)? else {
        transaction.rollback()?;
        return Ok(None);
    };
    if hold.released_at.is_some() {
        transaction.rollback()?;
        return Ok(Some(hold));
    }

    let released_at = ActionEntry::canonical_timestamp(&released_at);
    transaction.execute(
        "UPDATE legal_holds
         SET released_at = ?2,
             release_reason = ?3
         WHERE id = ?1",
        params![hold_id, released_at, release_reason],
    )?;
    insert_legal_hold_event(
        &transaction,
        hold_id,
        hold.org_id.as_deref(),
        "released",
        &released_at,
        release_reason,
    )?;
    transaction.commit()?;

    hold.released_at = Some(released_at);
    hold.release_reason = Some(release_reason.to_string());

    Ok(Some(hold))
}

fn load_legal_holds(conn: &Connection, org_id: Option<&str>) -> Result<Vec<LegalHoldRecord>> {
    let sql = if org_id.is_some() {
        "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
         FROM legal_holds
         WHERE org_id = ?1
         ORDER BY created_at ASC, id ASC"
    } else {
        "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
         FROM legal_holds
         ORDER BY created_at ASC, id ASC"
    };
    let mut statement = conn.prepare(sql)?;
    let mut rows = if let Some(org_id) = org_id {
        statement.query(params![org_id])?
    } else {
        statement.query([])?
    };

    let mut holds = Vec::new();
    while let Some(row) = rows.next()? {
        holds.push(LegalHoldRecord {
            id: row.get(0)?,
            org_id: row.get(1)?,
            matter: row.get(2)?,
            reason: row.get(3)?,
            created_at: row.get(4)?,
            released_at: row.get(5)?,
            release_reason: row.get(6)?,
        });
    }

    Ok(holds)
}

fn load_legal_hold_events(conn: &Connection, hold_id: &str) -> Result<Vec<LegalHoldEvent>> {
    let mut statement = conn.prepare(
        "SELECT id, hold_id, org_id, event_type, occurred_at, detail
         FROM legal_hold_events
         WHERE hold_id = ?1
         ORDER BY occurred_at ASC, id ASC",
    )?;
    let rows = statement.query_map(params![hold_id], |row| {
        Ok(LegalHoldEvent {
            id: row.get(0)?,
            hold_id: row.get(1)?,
            org_id: row.get(2)?,
            event_type: row.get(3)?,
            occurred_at: row.get(4)?,
            detail: row.get(5)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

fn load_legal_hold(conn: &Connection, hold_id: &str) -> Result<Option<LegalHoldRecord>> {
    conn.query_row(
        "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
         FROM legal_holds
         WHERE id = ?1",
        params![hold_id],
        |row| {
            Ok(LegalHoldRecord {
                id: row.get(0)?,
                org_id: row.get(1)?,
                matter: row.get(2)?,
                reason: row.get(3)?,
                created_at: row.get(4)?,
                released_at: row.get(5)?,
                release_reason: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn insert_legal_hold_event(
    conn: &Connection,
    hold_id: &str,
    org_id: Option<&str>,
    event_type: &str,
    occurred_at: &str,
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO legal_hold_events (
            id,
            hold_id,
            org_id,
            event_type,
            occurred_at,
            detail
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            Uuid::new_v4().to_string(),
            hold_id,
            org_id,
            event_type,
            occurred_at,
            detail,
        ],
    )?;

    Ok(())
}

fn has_active_legal_hold(conn: &Connection, org_id: Option<&str>) -> Result<bool> {
    let scope = load_active_hold_scope(conn)?;
    Ok(scope.global || org_id.is_some_and(|org_id| scope.org_ids.contains(org_id)))
}

fn load_active_hold_scope(conn: &Connection) -> Result<ActiveHoldScope> {
    let mut statement = conn.prepare(
        "SELECT org_id
         FROM legal_holds
         WHERE released_at IS NULL",
    )?;
    let mut rows = statement.query([])?;
    let mut scope = ActiveHoldScope::default();

    while let Some(row) = rows.next()? {
        let org_id = row.get::<_, Option<String>>(0)?;
        match org_id {
            Some(org_id) => {
                scope.org_ids.insert(org_id);
            }
            None => scope.global = true,
        }
    }

    Ok(scope)
}

fn load_org_retention_days(conn: &Connection) -> Result<HashMap<String, i64>> {
    let mut statement = conn.prepare(
        "SELECT org_id, min_retention_days
         FROM org_retention_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;

    let mut policies = HashMap::new();
    for row in rows {
        let (org_id, min_retention_days) = row?;
        policies.insert(org_id, min_retention_days.max(0));
    }

    Ok(policies)
}
