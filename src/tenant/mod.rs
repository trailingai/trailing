use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use uuid::Uuid;

pub const DEFAULT_ORG_SLUG: &str = "default";
pub const DEFAULT_PROJECT_SLUG: &str = "default-project";
const DEFAULT_ORG_ID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
    pub settings_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub org_id: String,
    pub project_id: String,
}

pub fn initialize_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            settings_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(org_id, slug)
        );

        CREATE INDEX IF NOT EXISTS idx_projects_org_id
        ON projects (org_id);
        ",
    )
}

pub fn ensure_default_catalog(conn: &Connection) -> rusqlite::Result<TenantContext> {
    let organization = match find_organization_by_slug(conn, DEFAULT_ORG_SLUG)? {
        Some(organization) => organization,
        None => insert_organization(
            conn,
            DEFAULT_ORG_ID.to_string(),
            "Default Organization",
            DEFAULT_ORG_SLUG,
            "{}",
        )?,
    };
    let project = ensure_default_project_for_org(conn, &organization.id)?;

    Ok(TenantContext {
        org_id: organization.id,
        project_id: project.id,
    })
}

pub fn ensure_organization_id(conn: &Connection, org_id: &str) -> rusqlite::Result<Organization> {
    match get_organization(conn, org_id)? {
        Some(organization) => Ok(organization),
        None => {
            let slug = unique_org_slug(conn, &format!("org-{}", slugify(org_id)))?;
            insert_organization(
                conn,
                org_id.to_string(),
                &format!("Legacy Organization {}", short_label(org_id)),
                &slug,
                "{}",
            )
        }
    }
}

pub fn create_organization(
    conn: &Connection,
    name: &str,
    slug: &str,
    settings_json: &str,
) -> rusqlite::Result<Organization> {
    insert_organization(conn, Uuid::new_v4().to_string(), name, slug, settings_json)
}

pub fn get_organization(conn: &Connection, id: &str) -> rusqlite::Result<Option<Organization>> {
    conn.query_row(
        "SELECT id, name, slug, created_at, settings_json
         FROM organizations
         WHERE id = ?1",
        params![id],
        map_organization,
    )
    .optional()
}

pub fn list_organizations(conn: &Connection) -> rusqlite::Result<Vec<Organization>> {
    let mut statement = conn.prepare(
        "SELECT id, name, slug, created_at, settings_json
         FROM organizations
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], map_organization)?;

    let mut organizations = Vec::new();
    for row in rows {
        organizations.push(row?);
    }
    Ok(organizations)
}

pub fn update_organization(
    conn: &Connection,
    id: &str,
    name: &str,
    slug: &str,
    settings_json: &str,
) -> rusqlite::Result<Option<Organization>> {
    let changed = conn.execute(
        "UPDATE organizations
         SET name = ?2, slug = ?3, settings_json = ?4
         WHERE id = ?1",
        params![id, name, slug, settings_json],
    )?;

    if changed == 0 {
        return Ok(None);
    }

    get_organization(conn, id)
}

pub fn delete_organization(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM organizations WHERE id = ?1", params![id])? != 0)
}

pub fn create_project(
    conn: &Connection,
    org_id: &str,
    name: &str,
    slug: &str,
) -> rusqlite::Result<Project> {
    insert_project(conn, Uuid::new_v4().to_string(), org_id, name, slug)
}

pub fn get_project(conn: &Connection, id: &str) -> rusqlite::Result<Option<Project>> {
    conn.query_row(
        "SELECT id, org_id, name, slug, created_at
         FROM projects
         WHERE id = ?1",
        params![id],
        map_project,
    )
    .optional()
}

pub fn list_projects(conn: &Connection, org_id: Option<&str>) -> rusqlite::Result<Vec<Project>> {
    let mut statement = if org_id.is_some() {
        conn.prepare(
            "SELECT id, org_id, name, slug, created_at
             FROM projects
             WHERE org_id = ?1
             ORDER BY created_at ASC, id ASC",
        )?
    } else {
        conn.prepare(
            "SELECT id, org_id, name, slug, created_at
             FROM projects
             ORDER BY created_at ASC, id ASC",
        )?
    };
    let rows = if let Some(org_id) = org_id {
        statement.query_map(params![org_id], map_project)?
    } else {
        statement.query_map([], map_project)?
    };

    let mut projects = Vec::new();
    for row in rows {
        projects.push(row?);
    }
    Ok(projects)
}

pub fn update_project(
    conn: &Connection,
    id: &str,
    name: &str,
    slug: &str,
) -> rusqlite::Result<Option<Project>> {
    let changed = conn.execute(
        "UPDATE projects
         SET name = ?2, slug = ?3
         WHERE id = ?1",
        params![id, name, slug],
    )?;

    if changed == 0 {
        return Ok(None);
    }

    get_project(conn, id)
}

pub fn delete_project(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM projects WHERE id = ?1", params![id])? != 0)
}

pub fn ensure_default_project_for_org(
    conn: &Connection,
    org_id: &str,
) -> rusqlite::Result<Project> {
    conn.query_row(
        "SELECT id, org_id, name, slug, created_at
         FROM projects
         WHERE org_id = ?1 AND slug = ?2",
        params![org_id, DEFAULT_PROJECT_SLUG],
        map_project,
    )
    .optional()?
    .map_or_else(
        || {
            insert_project(
                conn,
                Uuid::new_v4().to_string(),
                org_id,
                "Default Project",
                DEFAULT_PROJECT_SLUG,
            )
        },
        Ok,
    )
}

pub fn bootstrap_legacy_organizations(conn: &Connection) -> rusqlite::Result<()> {
    let default_org_id = ensure_default_catalog(conn)?.org_id;

    let has_api_keys: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_keys'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    let query = if has_api_keys {
        "SELECT DISTINCT org_id
         FROM (
             SELECT org_id FROM action_log
             UNION
             SELECT org_id FROM api_keys
         )
         WHERE org_id IS NOT NULL AND TRIM(org_id) <> ''"
    } else {
        "SELECT DISTINCT org_id
         FROM action_log
         WHERE org_id IS NOT NULL AND TRIM(org_id) <> ''"
    };

    let mut statement = conn.prepare(query)?;
    let ids = statement.query_map([], |row| row.get::<_, String>(0))?;

    for id in ids {
        let id = id?;
        if id == default_org_id {
            continue;
        }
        ensure_organization_id(conn, &id)?;
    }

    Ok(())
}

pub fn migrate_action_log_schema(conn: &Connection) -> rusqlite::Result<TenantContext> {
    let default_context = ensure_default_catalog(conn)?;
    bootstrap_legacy_organizations(conn)?;

    let organization_ids = list_organizations(conn)?
        .into_iter()
        .map(|organization| organization.id)
        .collect::<Vec<_>>();
    for organization_id in organization_ids {
        ensure_default_project_for_org(conn, &organization_id)?;
    }

    if !table_has_column(conn, "action_log", "org_id")? {
        conn.execute("ALTER TABLE action_log ADD COLUMN org_id TEXT", [])?;
    }
    if !table_has_column(conn, "action_log", "project_id")? {
        conn.execute("ALTER TABLE action_log ADD COLUMN project_id TEXT", [])?;
    }

    conn.execute(
        "UPDATE action_log
         SET org_id = ?1
         WHERE org_id IS NULL OR TRIM(org_id) = ''",
        params![default_context.org_id],
    )?;
    conn.execute(
        "UPDATE action_log
         SET project_id = (
             SELECT id
             FROM projects
             WHERE projects.org_id = action_log.org_id
               AND projects.slug = ?1
             LIMIT 1
         )
         WHERE project_id IS NULL OR TRIM(project_id) = ''",
        params![DEFAULT_PROJECT_SLUG],
    )?;

    if action_log_needs_rebuild(conn)? {
        rebuild_action_log(conn)?;
    }

    Ok(default_context)
}

fn insert_organization(
    conn: &Connection,
    id: String,
    name: &str,
    slug: &str,
    settings_json: &str,
) -> rusqlite::Result<Organization> {
    let created_at = current_timestamp();
    conn.execute(
        "INSERT INTO organizations (
            id,
            name,
            slug,
            created_at,
            settings_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, name, slug, created_at, settings_json],
    )?;

    Ok(Organization {
        id,
        name: name.to_string(),
        slug: slug.to_string(),
        created_at,
        settings_json: settings_json.to_string(),
    })
}

fn insert_project(
    conn: &Connection,
    id: String,
    org_id: &str,
    name: &str,
    slug: &str,
) -> rusqlite::Result<Project> {
    let created_at = current_timestamp();
    conn.execute(
        "INSERT INTO projects (
            id,
            org_id,
            name,
            slug,
            created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, org_id, name, slug, created_at],
    )?;

    Ok(Project {
        id,
        org_id: org_id.to_string(),
        name: name.to_string(),
        slug: slug.to_string(),
        created_at,
    })
}

fn find_organization_by_slug(
    conn: &Connection,
    slug: &str,
) -> rusqlite::Result<Option<Organization>> {
    conn.query_row(
        "SELECT id, name, slug, created_at, settings_json
         FROM organizations
         WHERE slug = ?1",
        params![slug],
        map_organization,
    )
    .optional()
}

fn map_organization(row: &rusqlite::Row<'_>) -> rusqlite::Result<Organization> {
    Ok(Organization {
        id: row.get(0)?,
        name: row.get(1)?,
        slug: row.get(2)?,
        created_at: row.get(3)?,
        settings_json: row.get(4)?,
    })
}

fn map_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        slug: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn current_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_dash = false;

    for character in value.chars() {
        let lower = character.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            previous_was_dash = false;
        } else if !previous_was_dash {
            slug.push('-');
            previous_was_dash = true;
        }
    }

    slug.trim_matches('-').to_string()
}

fn short_label(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

fn unique_org_slug(conn: &Connection, base_slug: &str) -> rusqlite::Result<String> {
    let base_slug = if base_slug.trim().is_empty() {
        "org".to_string()
    } else {
        base_slug.trim().to_string()
    };

    if !organization_slug_exists(conn, &base_slug)? {
        return Ok(base_slug);
    }

    let mut counter = 2usize;
    loop {
        let candidate = format!("{base_slug}-{counter}");
        if !organization_slug_exists(conn, &candidate)? {
            return Ok(candidate);
        }
        counter += 1;
    }
}

fn organization_slug_exists(conn: &Connection, slug: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM organizations WHERE slug = ?1 LIMIT 1",
        params![slug],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|row| row.is_some())
}

fn action_log_needs_rebuild(conn: &Connection) -> rusqlite::Result<bool> {
    let org_not_null = column_is_not_null(conn, "action_log", "org_id")?;
    let project_not_null = column_is_not_null(conn, "action_log", "project_id")?;
    Ok(!org_not_null || !project_not_null)
}

fn column_is_not_null(
    conn: &Connection,
    table_name: &str,
    column_name: &str,
) -> rusqlite::Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let mut rows = statement.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column_name {
            return row.get::<_, i64>(3).map(|value| value != 0);
        }
    }

    Ok(false)
}

fn table_has_column(
    conn: &Connection,
    table_name: &str,
    column_name: &str,
) -> rusqlite::Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let mut rows = statement.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column_name {
            return Ok(true);
        }
    }

    Ok(false)
}

fn rebuild_action_log(conn: &Connection) -> rusqlite::Result<()> {
    let transaction = conn.unchecked_transaction()?;
    transaction.execute_batch(
        "
        DROP TRIGGER IF EXISTS action_log_reject_update;
        DROP TRIGGER IF EXISTS action_log_reject_delete;
        DROP INDEX IF EXISTS idx_action_log_org_id;
        DROP TABLE IF EXISTS action_log__new;

        CREATE TABLE action_log__new (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            agent_type TEXT NOT NULL,
            session_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            context TEXT NOT NULL,
            outcome TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT
        );
        ",
    )?;
    transaction.execute(
        "INSERT INTO action_log__new (
            sequence,
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id
        )
        SELECT
            sequence,
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id
        FROM action_log
        ORDER BY sequence ASC",
        [],
    )?;
    transaction.execute_batch(
        "
        DROP TABLE action_log;
        ALTER TABLE action_log__new RENAME TO action_log;
        ",
    )?;
    transaction.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_and_project_crud_round_trip() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        initialize_schema(&conn).expect("initialize tenant schema");
        let default_context = ensure_default_catalog(&conn).expect("default catalog");

        let organization = create_organization(&conn, "Acme", "acme", r#"{"tier":"pro"}"#)
            .expect("create organization");
        let listed_organizations = list_organizations(&conn).expect("list organizations");
        assert!(
            listed_organizations
                .iter()
                .any(|item| item.id == default_context.org_id)
        );
        assert!(
            listed_organizations
                .iter()
                .any(|item| item.id == organization.id)
        );

        let updated_organization = update_organization(
            &conn,
            &organization.id,
            "Acme Co",
            "acme-co",
            r#"{"tier":"enterprise"}"#,
        )
        .expect("update organization")
        .expect("organization exists");
        assert_eq!(updated_organization.name, "Acme Co");
        assert_eq!(updated_organization.slug, "acme-co");
        assert_eq!(
            updated_organization.settings_json,
            r#"{"tier":"enterprise"}"#
        );

        let project =
            create_project(&conn, &organization.id, "Infra", "infra").expect("create project");
        let listed_projects = list_projects(&conn, Some(&organization.id)).expect("list projects");
        assert!(listed_projects.iter().any(|item| item.id == project.id));

        let updated_project = update_project(&conn, &project.id, "Core Infra", "core-infra")
            .expect("update project")
            .expect("project exists");
        assert_eq!(updated_project.name, "Core Infra");
        assert_eq!(updated_project.slug, "core-infra");

        assert!(delete_project(&conn, &project.id).expect("delete project"));
        assert!(delete_organization(&conn, &organization.id).expect("delete organization"));
        assert!(
            get_organization(&conn, &organization.id)
                .expect("get deleted organization")
                .is_none()
        );
    }
}
