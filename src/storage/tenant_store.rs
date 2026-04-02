use super::*;

impl Storage {
    pub fn saml_config(&self, org_id: &str) -> Result<Option<SamlIdpConfig>> {
        match self {
            Self::Sqlite(storage) => storage.saml_config(org_id),
            Self::Postgres(_) => Ok(None),
        }
    }

    pub fn upsert_saml_config(
        &self,
        org_id: &str,
        input: UpsertSamlIdpConfig,
    ) -> Result<SamlIdpConfig> {
        match self {
            Self::Sqlite(storage) => storage.upsert_saml_config(org_id, input),
            Self::Postgres(_) => Err(StorageError::InvalidInput(
                "saml idp configuration is only available for sqlite storage".to_string(),
            )),
        }
    }

    pub fn tenant_context(&self) -> Result<TenantContext> {
        match self {
            Self::Sqlite(storage) => storage.tenant_context(),
            Self::Postgres(_) => Err(StorageError::InvalidInput(
                "tenant catalog is only available for sqlite storage".to_string(),
            )),
        }
    }

    pub fn get_org_settings(&self, org_id: &str) -> Result<Option<OrgSettings>> {
        match self {
            Self::Sqlite(storage) => storage.get_org_settings(org_id),
            Self::Postgres(_) => Ok(None),
        }
    }

    pub fn upsert_org_settings(
        &self,
        org_id: &str,
        input: OrgSettingsInput,
    ) -> Result<(OrgSettings, bool)> {
        match self {
            Self::Sqlite(storage) => storage.upsert_org_settings(org_id, input),
            Self::Postgres(_) => Err(StorageError::InvalidInput(
                "organization settings are only available for sqlite storage".to_string(),
            )),
        }
    }

    pub fn delete_org_settings(&self, org_id: &str) -> Result<bool> {
        match self {
            Self::Sqlite(storage) => storage.delete_org_settings(org_id),
            Self::Postgres(_) => Ok(false),
        }
    }
}

impl SqliteStorage {
    pub fn tenant_context(&self) -> Result<TenantContext> {
        tenant::ensure_default_catalog(&self.conn).map_err(StorageError::from)
    }

    pub fn create_organization(
        &self,
        name: &str,
        slug: &str,
        settings_json: &str,
    ) -> Result<Organization> {
        validate_tenant_value(name, "organization name")?;
        validate_tenant_value(slug, "organization slug")?;
        tenant::create_organization(&self.conn, name.trim(), slug.trim(), settings_json)
            .map_err(StorageError::from)
    }

    pub fn get_organization(&self, id: &str) -> Result<Option<Organization>> {
        tenant::get_organization(&self.conn, id).map_err(StorageError::from)
    }

    pub fn list_organizations(&self) -> Result<Vec<Organization>> {
        tenant::list_organizations(&self.conn).map_err(StorageError::from)
    }

    pub fn update_organization(
        &self,
        id: &str,
        name: &str,
        slug: &str,
        settings_json: &str,
    ) -> Result<Option<Organization>> {
        validate_tenant_value(name, "organization name")?;
        validate_tenant_value(slug, "organization slug")?;
        tenant::update_organization(&self.conn, id, name.trim(), slug.trim(), settings_json)
            .map_err(StorageError::from)
    }

    pub fn delete_organization(&self, id: &str) -> Result<bool> {
        let default_context = self.tenant_context()?;
        if id == default_context.org_id {
            return Err(StorageError::InvalidInput(
                "default organization cannot be deleted".to_string(),
            ));
        }

        tenant::delete_organization(&self.conn, id).map_err(StorageError::from)
    }

    pub fn create_project(&self, org_id: &str, name: &str, slug: &str) -> Result<Project> {
        validate_tenant_value(org_id, "organization id")?;
        validate_tenant_value(name, "project name")?;
        validate_tenant_value(slug, "project slug")?;
        tenant::create_project(&self.conn, org_id.trim(), name.trim(), slug.trim())
            .map_err(StorageError::from)
    }

    pub fn get_project(&self, id: &str) -> Result<Option<Project>> {
        tenant::get_project(&self.conn, id).map_err(StorageError::from)
    }

    pub fn list_projects(&self, org_id: Option<&str>) -> Result<Vec<Project>> {
        tenant::list_projects(&self.conn, org_id).map_err(StorageError::from)
    }

    pub fn update_project(&self, id: &str, name: &str, slug: &str) -> Result<Option<Project>> {
        validate_tenant_value(name, "project name")?;
        validate_tenant_value(slug, "project slug")?;
        tenant::update_project(&self.conn, id, name.trim(), slug.trim()).map_err(StorageError::from)
    }

    pub fn delete_project(&self, id: &str) -> Result<bool> {
        let default_context = self.tenant_context()?;
        if id == default_context.project_id {
            return Err(StorageError::InvalidInput(
                "default project cannot be deleted".to_string(),
            ));
        }

        tenant::delete_project(&self.conn, id).map_err(StorageError::from)
    }

    pub fn get_org_settings(&self, org_id: &str) -> Result<Option<OrgSettings>> {
        load_org_settings(&self.conn, org_id)
    }

    pub fn upsert_org_settings(
        &self,
        org_id: &str,
        input: OrgSettingsInput,
    ) -> Result<(OrgSettings, bool)> {
        let org_id = normalize_org_id(org_id)?;
        let retention_policy = normalize_json_object(input.retention_policy, "retention_policy")?;
        let enabled_frameworks = normalize_enabled_frameworks(input.enabled_frameworks)?;
        let guardrail_settings =
            normalize_json_object(input.guardrail_settings, "guardrail_settings")?;
        let updated_at = ActionEntry::canonical_timestamp(&current_time());
        let created_at = self
            .conn
            .query_row(
                "SELECT created_at FROM org_settings WHERE org_id = ?1",
                params![org_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let created = created_at.is_none();
        let created_at = created_at.unwrap_or_else(|| updated_at.clone());

        self.conn.execute(
            "INSERT INTO org_settings (
                org_id,
                retention_policy,
                enabled_frameworks,
                guardrail_settings,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(org_id) DO UPDATE SET
                retention_policy = excluded.retention_policy,
                enabled_frameworks = excluded.enabled_frameworks,
                guardrail_settings = excluded.guardrail_settings,
                updated_at = excluded.updated_at",
            params![
                org_id.as_str(),
                retention_policy.to_string(),
                serde_json::to_string(&enabled_frameworks)?,
                guardrail_settings.to_string(),
                created_at.as_str(),
                updated_at.as_str(),
            ],
        )?;

        Ok((
            OrgSettings {
                org_id,
                retention_policy,
                enabled_frameworks,
                guardrail_settings,
                created_at,
                updated_at,
            },
            created,
        ))
    }

    pub fn delete_org_settings(&self, org_id: &str) -> Result<bool> {
        let org_id = normalize_org_id(org_id)?;
        let deleted = self.conn.execute(
            "DELETE FROM org_settings WHERE org_id = ?1",
            params![org_id.as_str()],
        )?;
        Ok(deleted > 0)
    }

    pub fn upsert_saml_config(
        &self,
        org_id: &str,
        input: UpsertSamlIdpConfig,
    ) -> Result<SamlIdpConfig> {
        let org_id = require_non_empty(org_id, "organization id")?;
        let idp_entity_id = require_non_empty(&input.idp_entity_id, "IdP entity id")?;
        let sso_url = require_non_empty(&input.sso_url, "IdP SSO URL")?;
        let idp_certificate_pem = require_non_empty(&input.idp_certificate_pem, "IdP certificate")?;
        let sp_entity_id = require_non_empty(&input.sp_entity_id, "SP entity id")?;
        let acs_url = require_non_empty(&input.acs_url, "ACS URL")?;
        let email_attribute = require_non_empty(&input.email_attribute, "email attribute")?;
        let default_role = normalize_internal_role(&input.default_role)?;
        let role_mappings = normalize_role_mappings(input.role_mappings)?;
        let first_name_attribute = optional_trimmed(input.first_name_attribute);
        let last_name_attribute = optional_trimmed(input.last_name_attribute);
        let role_attribute = optional_trimmed(input.role_attribute);
        let now = ActionEntry::canonical_timestamp(&current_time());

        self.conn.execute(
            "INSERT INTO saml_idp_configs (
                org_id,
                enabled,
                idp_entity_id,
                sso_url,
                idp_certificate_pem,
                sp_entity_id,
                acs_url,
                email_attribute,
                first_name_attribute,
                last_name_attribute,
                role_attribute,
                role_mappings,
                default_role,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            ON CONFLICT(org_id) DO UPDATE SET
                enabled = excluded.enabled,
                idp_entity_id = excluded.idp_entity_id,
                sso_url = excluded.sso_url,
                idp_certificate_pem = excluded.idp_certificate_pem,
                sp_entity_id = excluded.sp_entity_id,
                acs_url = excluded.acs_url,
                email_attribute = excluded.email_attribute,
                first_name_attribute = excluded.first_name_attribute,
                last_name_attribute = excluded.last_name_attribute,
                role_attribute = excluded.role_attribute,
                role_mappings = excluded.role_mappings,
                default_role = excluded.default_role,
                updated_at = excluded.updated_at",
            params![
                org_id,
                i64::from(input.enabled),
                &idp_entity_id,
                &sso_url,
                &idp_certificate_pem,
                &sp_entity_id,
                &acs_url,
                &email_attribute,
                &first_name_attribute,
                &last_name_attribute,
                &role_attribute,
                serde_json::to_string(&role_mappings)?,
                &default_role,
                &now,
                &now,
            ],
        )?;

        self.saml_config(&org_id)?
            .ok_or_else(|| StorageError::InvalidInput("failed to store SAML config".to_string()))
    }

    pub fn saml_config(&self, org_id: &str) -> Result<Option<SamlIdpConfig>> {
        let org_id = org_id.trim();
        if org_id.is_empty() {
            return Ok(None);
        }

        load_saml_config(&self.conn, org_id)
    }
}

fn load_org_settings(conn: &Connection, org_id: &str) -> Result<Option<OrgSettings>> {
    let org_id = normalize_org_id(org_id)?;

    conn.query_row(
        "SELECT org_id, retention_policy, enabled_frameworks, guardrail_settings, created_at, updated_at
         FROM org_settings
         WHERE org_id = ?1",
        params![org_id.as_str()],
        |row| {
            let retention_policy = row.get::<_, String>(1)?;
            let enabled_frameworks = row.get::<_, String>(2)?;
            let guardrail_settings = row.get::<_, String>(3)?;

            Ok(OrgSettings {
                org_id: row.get(0)?,
                retention_policy: serde_json::from_str(&retention_policy).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                enabled_frameworks: serde_json::from_str(&enabled_frameworks).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                guardrail_settings: serde_json::from_str(&guardrail_settings).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_saml_config(conn: &Connection, org_id: &str) -> Result<Option<SamlIdpConfig>> {
    conn.query_row(
        "SELECT org_id, enabled, idp_entity_id, sso_url, idp_certificate_pem, sp_entity_id, acs_url,
                email_attribute, first_name_attribute, last_name_attribute, role_attribute,
                role_mappings, default_role, created_at, updated_at
         FROM saml_idp_configs
         WHERE org_id = ?1",
        params![org_id],
        |row| {
            Ok(SamlIdpConfig {
                org_id: row.get(0)?,
                enabled: row.get::<_, i64>(1)? != 0,
                idp_entity_id: row.get(2)?,
                sso_url: row.get(3)?,
                idp_certificate_pem: row.get(4)?,
                sp_entity_id: row.get(5)?,
                acs_url: row.get(6)?,
                email_attribute: row.get(7)?,
                first_name_attribute: row.get(8)?,
                last_name_attribute: row.get(9)?,
                role_attribute: row.get(10)?,
                role_mappings: serde_json::from_str(&row.get::<_, String>(11)?).map_err(
                    |error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            11,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    },
                )?,
                default_role: row.get(12)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn validate_tenant_value(value: &str, field_name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(StorageError::InvalidInput(format!(
            "{field_name} must not be empty"
        )));
    }

    Ok(())
}

fn normalize_org_id(org_id: &str) -> Result<String> {
    let org_id = org_id.trim();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }

    Ok(org_id.to_string())
}

fn normalize_json_object(value: Value, field_name: &str) -> Result<Value> {
    match value {
        Value::Null => Ok(json!({})),
        Value::Object(_) => Ok(value),
        _ => Err(StorageError::InvalidInput(format!(
            "{field_name} must be a JSON object"
        ))),
    }
}

fn normalize_enabled_frameworks(values: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    if normalized.iter().any(String::is_empty) {
        return Err(StorageError::InvalidInput(
            "enabled_frameworks must not contain empty values".to_string(),
        ));
    }

    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}
