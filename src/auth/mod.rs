use std::process::Command;

use chrono::{DateTime, Utc};
use uuid::Uuid;

const TOTP_STEP_SECONDS: i64 = 30;
const DEFAULT_TOTP_WINDOW: i64 = 1;
const INGEST_PERMISSIONS: &[&str] = &["ingest"];
const QUERY_PERMISSIONS: &[&str] = &["query"];
const EXPORT_PERMISSIONS: &[&str] = &["query", "export"];
const CONFIGURE_PERMISSIONS: &[&str] = &["configure"];
const MANAGE_KEYS_PERMISSIONS: &[&str] = &["manage_keys"];
const DEVELOPER_PERMISSIONS: &[&str] =
    &["ingest", "query", "export", "configure", "manage_keys"];
const COMPLIANCE_OFFICER_PERMISSIONS: &[&str] = &["query", "export", "configure"];
const ADMIN_PERMISSIONS: &[&str] = &[
    "ingest",
    "query",
    "export",
    "configure",
    "manage_keys",
    "admin",
];
const TOTP_PYTHON_SCRIPT: &str = r#"
import base64
import hashlib
import hmac
import secrets
import sys

def decode_secret(secret):
    secret = secret.strip().upper()
    padding = '=' * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding, casefold=True)

def hotp(secret, counter):
    key = decode_secret(secret)
    msg = counter.to_bytes(8, 'big')
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return f"{binary % 1000000:06d}"

mode = sys.argv[1]

if mode == "generate_secret":
    print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))
elif mode == "code":
    secret = sys.argv[2]
    timestamp = int(sys.argv[3])
    print(hotp(secret, timestamp // 30))
elif mode == "verify":
    secret = sys.argv[2]
    code = sys.argv[3].strip()
    timestamp = int(sys.argv[4])
    window = int(sys.argv[5])
    current_counter = timestamp // 30
    verified = any(
        hotp(secret, current_counter + offset) == code
        for offset in range(-window, window + 1)
    )
    print("true" if verified else "false")
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleDefinition {
    pub name: &'static str,
    pub permissions: &'static [&'static str],
}

const API_KEY_ROLE_DEFINITIONS: &[RoleDefinition] = &[
    RoleDefinition {
        name: "admin",
        permissions: ADMIN_PERMISSIONS,
    },
    RoleDefinition {
        name: "ingest",
        permissions: INGEST_PERMISSIONS,
    },
    RoleDefinition {
        name: "query",
        permissions: QUERY_PERMISSIONS,
    },
    RoleDefinition {
        name: "export",
        permissions: EXPORT_PERMISSIONS,
    },
    RoleDefinition {
        name: "configure",
        permissions: CONFIGURE_PERMISSIONS,
    },
    RoleDefinition {
        name: "manage_keys",
        permissions: MANAGE_KEYS_PERMISSIONS,
    },
];

const PRINCIPAL_ROLE_DEFINITIONS: &[RoleDefinition] = &[
    RoleDefinition {
        name: "admin",
        permissions: ADMIN_PERMISSIONS,
    },
    RoleDefinition {
        name: "developer",
        permissions: DEVELOPER_PERMISSIONS,
    },
    RoleDefinition {
        name: "compliance_officer",
        permissions: COMPLIANCE_OFFICER_PERMISSIONS,
    },
    RoleDefinition {
        name: "auditor",
        permissions: EXPORT_PERMISSIONS,
    },
    RoleDefinition {
        name: "viewer",
        permissions: QUERY_PERMISSIONS,
    },
    RoleDefinition {
        name: "read_only",
        permissions: QUERY_PERMISSIONS,
    },
];

pub fn api_key_role_definitions() -> &'static [RoleDefinition] {
    API_KEY_ROLE_DEFINITIONS
}

pub fn principal_role_definitions() -> &'static [RoleDefinition] {
    PRINCIPAL_ROLE_DEFINITIONS
}

pub fn role_grants_permission(role: &str, permission: &str) -> bool {
    permissions_for_role(role).contains(&permission)
}

fn permissions_for_role(role: &str) -> &'static [&'static str] {
    match role.trim() {
        "admin" => ADMIN_PERMISSIONS,
        "member" | "developer" => DEVELOPER_PERMISSIONS,
        "compliance_officer" => COMPLIANCE_OFFICER_PERMISSIONS,
        "auditor" | "export" => EXPORT_PERMISSIONS,
        "viewer" | "read_only" | "query" => QUERY_PERMISSIONS,
        "ingest" => INGEST_PERMISSIONS,
        "configure" => CONFIGURE_PERMISSIONS,
        "manage_keys" => MANAGE_KEYS_PERMISSIONS,
        _ => &[],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCodeCount {
    Default,
}

impl RecoveryCodeCount {
    fn value(self) -> usize {
        match self {
            Self::Default => 8,
        }
    }
}

pub fn generate_totp_secret() -> Result<String, String> {
    let output = Command::new("python3")
        .args(["-c", TOTP_PYTHON_SCRIPT, "generate_secret"])
        .output()
        .map_err(|error| error.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn verify_totp(secret: &str, code: &str, timestamp: DateTime<Utc>) -> Result<bool, String> {
    let output = Command::new("python3")
        .args([
            "-c",
            TOTP_PYTHON_SCRIPT,
            "verify",
            secret,
            code.trim(),
            &timestamp.timestamp().to_string(),
            &DEFAULT_TOTP_WINDOW.to_string(),
        ])
        .output()
        .map_err(|error| error.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

pub fn provisioning_uri(email: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/Trailing:{email}?secret={secret}&issuer=Trailing&period={TOTP_STEP_SECONDS}"
    )
}

pub fn generate_recovery_codes(count: RecoveryCodeCount) -> Vec<String> {
    (0..count.value())
        .map(|_| {
            let token = Uuid::new_v4().to_string().replace('-', "").to_uppercase();
            format!("{}-{}", &token[..4], &token[28..32])
        })
        .collect()
}

#[cfg(test)]
pub fn totp_code_for_timestamp(secret: &str, timestamp: DateTime<Utc>) -> Result<String, String> {
    let output = Command::new("python3")
        .args([
            "-c",
            TOTP_PYTHON_SCRIPT,
            "code",
            secret,
            &timestamp.timestamp().to_string(),
        ])
        .output()
        .map_err(|error| error.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{
        RecoveryCodeCount, generate_recovery_codes, generate_totp_secret, totp_code_for_timestamp,
        verify_totp,
    };

    #[test]
    fn generated_recovery_codes_are_unique() {
        let codes = generate_recovery_codes(RecoveryCodeCount::Default);
        let unique = codes.iter().collect::<std::collections::BTreeSet<_>>();

        assert_eq!(codes.len(), 8);
        assert_eq!(unique.len(), 8);
        assert!(codes.iter().all(|code| code.len() == 9));
    }

    #[test]
    fn generated_totp_secret_can_round_trip_a_code() {
        let secret = generate_totp_secret().expect("generate secret");
        let timestamp = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();
        let code = totp_code_for_timestamp(&secret, timestamp).expect("generate code");

        assert!(verify_totp(&secret, &code, timestamp).expect("verify totp"));
        assert!(!verify_totp(&secret, "000000", timestamp).expect("reject invalid code"));
    }
}
