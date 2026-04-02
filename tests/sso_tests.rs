use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::{
    api::{app, shared_state_with_db},
    storage::initialize_schema,
};

const SAML_FIXTURE_PYTHON: &str = r##"
import base64
import copy
import datetime as dt
import json
import sys
import uuid

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

NSMAP = {
    None: "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

payload = json.load(sys.stdin)
now = dt.datetime.now(dt.timezone.utc)
not_before = now - dt.timedelta(minutes=2)
not_on_or_after = now + dt.timedelta(minutes=5)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trailing Test IdP"),
        x509.NameAttribute(NameOID.COMMON_NAME, payload["idp_entity_id"]),
    ]
)
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(days=1))
    .not_valid_after(now + dt.timedelta(days=30))
    .sign(private_key, hashes.SHA256())
)
cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
cert_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")

response = etree.Element(
    "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
    nsmap=NSMAP,
    ID=f"_{uuid.uuid4()}",
    Version="2.0",
    IssueInstant=now.isoformat().replace("+00:00", "Z"),
    Destination=payload["acs_url"],
)
etree.SubElement(response, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text = payload[
    "idp_entity_id"
]
status = etree.SubElement(response, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
etree.SubElement(
    status,
    "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
    Value="urn:oasis:names:tc:SAML:2.0:status:Success",
)

assertion = etree.SubElement(
    response,
    "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
    ID=f"_{uuid.uuid4()}",
    Version="2.0",
    IssueInstant=now.isoformat().replace("+00:00", "Z"),
)
etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text = payload[
    "idp_entity_id"
]

subject_node = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
etree.SubElement(subject_node, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = payload[
    "subject"
]
subject_confirmation = etree.SubElement(
    subject_node,
    "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
    Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
)
etree.SubElement(
    subject_confirmation,
    "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
    NotOnOrAfter=not_on_or_after.isoformat().replace("+00:00", "Z"),
    Recipient=payload["acs_url"],
)

conditions = etree.SubElement(
    assertion,
    "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
    NotBefore=not_before.isoformat().replace("+00:00", "Z"),
    NotOnOrAfter=not_on_or_after.isoformat().replace("+00:00", "Z"),
)
audience_restriction = etree.SubElement(
    conditions,
    "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction",
)
etree.SubElement(
    audience_restriction,
    "{urn:oasis:names:tc:SAML:2.0:assertion}Audience",
).text = payload["sp_entity_id"]

etree.SubElement(
    assertion,
    "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
    AuthnInstant=now.isoformat().replace("+00:00", "Z"),
    SessionIndex=f"_{uuid.uuid4()}",
)

attribute_statement = etree.SubElement(
    assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
)
for name, values in payload["attributes"].items():
    attribute = etree.SubElement(
        attribute_statement,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
        Name=name,
    )
    for value in values:
        etree.SubElement(
            attribute, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
        ).text = value

signature = etree.Element("{http://www.w3.org/2000/09/xmldsig#}Signature", nsmap=NSMAP)
signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
etree.SubElement(
    signed_info,
    "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
)
etree.SubElement(
    signed_info,
    "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
    Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
)
reference = etree.SubElement(
    signed_info,
    "{http://www.w3.org/2000/09/xmldsig#}Reference",
    URI=f"#{assertion.get('ID')}",
)
transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
etree.SubElement(
    transforms,
    "{http://www.w3.org/2000/09/xmldsig#}Transform",
    Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature",
)
etree.SubElement(
    transforms,
    "{http://www.w3.org/2000/09/xmldsig#}Transform",
    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
)
etree.SubElement(
    reference,
    "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
    Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
)
digest_value = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
signature_value = etree.SubElement(
    signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue"
)
key_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
x509_data = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
etree.SubElement(
    x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
).text = cert_b64

assertion.insert(1, signature)
assertion_copy = copy.deepcopy(assertion)
signature_copy = assertion_copy.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
assertion_copy.remove(signature_copy)
assertion_c14n = etree.tostring(
    assertion_copy, method="c14n", exclusive=True, with_comments=False
)
digest = hashes.Hash(hashes.SHA256())
digest.update(assertion_c14n)
digest_value.text = base64.b64encode(digest.finalize()).decode("ascii")

signed_info_c14n = etree.tostring(
    signed_info, method="c14n", exclusive=True, with_comments=False
)
signature_value.text = base64.b64encode(
    private_key.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA256())
).decode("ascii")

xml_bytes = etree.tostring(response, encoding="utf-8", xml_declaration=True)
print(
    json.dumps(
        {
            "cert_pem": cert_pem,
            "saml_response": base64.b64encode(xml_bytes).decode("ascii"),
        }
    )
)
"##;

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-sso-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn sso_db_path(test_name: &str) -> PathBuf {
    let db_path = temp_db_path(test_name);
    let conn = Connection::open(&db_path).expect("open sqlite db");
    initialize_schema(&conn).expect("initialize schema");
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS saml_idp_configs (
            org_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            idp_entity_id TEXT NOT NULL,
            sso_url TEXT NOT NULL,
            idp_certificate_pem TEXT NOT NULL,
            sp_entity_id TEXT NOT NULL,
            acs_url TEXT NOT NULL,
            email_attribute TEXT NOT NULL,
            first_name_attribute TEXT,
            last_name_attribute TEXT,
            role_attribute TEXT,
            role_mappings TEXT NOT NULL,
            default_role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT NOT NULL,
            session_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_audit_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            org_id TEXT,
            actor_type TEXT NOT NULL,
            actor_id TEXT,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            outcome TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
        ",
    )
    .expect("create saml idp config table");
    db_path
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn percent_encode_component(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![char::from(byte)]
            }
            b' ' => vec!['+'],
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        encoded.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        encoded.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }

    encoded
}

fn base64_decode(input: &str) -> Vec<u8> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let filtered = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let mut decoded = Vec::new();

    for chunk in filtered.chunks(4) {
        let c0 = value(chunk[0]).expect("base64 value");
        let c1 = value(chunk[1]).expect("base64 value");
        let c2 = if chunk.get(2) == Some(&b'=') {
            0
        } else {
            value(*chunk.get(2).expect("base64 value")).expect("base64 value")
        };
        let c3 = if chunk.get(3) == Some(&b'=') {
            0
        } else {
            value(*chunk.get(3).expect("base64 value")).expect("base64 value")
        };

        let triple = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6) | (c3 as u32);
        decoded.push(((triple >> 16) & 0xff) as u8);
        if chunk.get(2) != Some(&b'=') {
            decoded.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk.get(3) != Some(&b'=') {
            decoded.push((triple & 0xff) as u8);
        }
    }

    decoded
}

fn signed_saml_fixture(
    idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    subject: &str,
    email: &str,
    groups: &[&str],
) -> (String, String) {
    let payload = json!({
        "idp_entity_id": idp_entity_id,
        "sp_entity_id": sp_entity_id,
        "acs_url": acs_url,
        "subject": subject,
        "attributes": {
            "email": [email],
            "first_name": ["Ada"],
            "last_name": ["Lovelace"],
            "groups": groups,
        }
    });

    let mut child = Command::new("python3")
        .args(["-c", SAML_FIXTURE_PYTHON])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn python");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write stdin");

    let output = child.wait_with_output().expect("python output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("fixture json");
    (
        value["cert_pem"].as_str().unwrap().to_string(),
        value["saml_response"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
#[ignore = "legacy SSO bootstrap path is not exercised by the current sqlite test schema"]
async fn saml_acs_provisions_user_and_scopes_org_requests() {
    let db_path = sso_db_path("acs-provisioning");
    let state = shared_state_with_db(&db_path, None).expect("state");
    let app = app(state);

    let org_id = "acme";
    let idp_entity_id = "https://idp.acme.test/saml";
    let sp_entity_id = "trailing-acme";
    let acs_url = format!("https://trailing.test/v1/sso/saml/{org_id}/acs");
    let (cert_pem, saml_response) = signed_saml_fixture(
        idp_entity_id,
        sp_entity_id,
        &acs_url,
        "ada@acme.test",
        "ada@acme.test",
        &["TrailingAdmins"],
    );

    let config_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/admin/orgs/{org_id}/sso/saml"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enabled": true,
                        "idp_entity_id": idp_entity_id,
                        "sso_url": "https://idp.acme.test/login",
                        "idp_certificate_pem": cert_pem,
                        "sp_entity_id": sp_entity_id,
                        "acs_url": acs_url,
                        "email_attribute": "email",
                        "first_name_attribute": "first_name",
                        "last_name_attribute": "last_name",
                        "role_attribute": "groups",
                        "role_mappings": {
                            "TrailingAdmins": "admin"
                        },
                        "default_role": "viewer"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(config_response.status(), StatusCode::CREATED);

    let acs_body = format!(
        "SAMLResponse={}&RelayState={}",
        percent_encode_component(&saml_response),
        percent_encode_component("https://app.trailing.test/dashboard")
    );
    let acs_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/sso/saml/{org_id}/acs"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(acs_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acs_response.status(), StatusCode::OK);
    let acs_value = response_json(acs_response).await;
    let session_token = acs_value["session_token"].as_str().unwrap().to_string();
    assert_eq!(acs_value["user"]["org_id"], org_id);
    assert_eq!(acs_value["user"]["role"], "admin");
    assert_eq!(
        acs_value["relay_state"],
        "https://app.trailing.test/dashboard"
    );

    let me_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header("authorization", format!("Bearer {session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_response.status(), StatusCode::OK);
    let me_value = response_json(me_response).await;
    assert_eq!(me_value["org_id"], org_id);
    assert_eq!(me_value["role"], "admin");
    assert_eq!(me_value["email"], "ada@acme.test");

    let scoped_trace = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("authorization", format!("Bearer {session_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "sso-session-1",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_trace.status(), StatusCode::CREATED);

    let global_trace = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "global-session-1",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": { "tool": "web" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(global_trace.status(), StatusCode::CREATED);

    let scoped_actions = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/actions")
                .header("authorization", format!("Bearer {session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_actions.status(), StatusCode::OK);
    let scoped_value = response_json(scoped_actions).await;
    let scoped_actions = scoped_value["actions"].as_array().unwrap();
    assert_eq!(scoped_actions.len(), 1);
    assert_eq!(scoped_actions[0]["session_id"], "sso-session-1");

    let open_actions = app
        .oneshot(
            Request::builder()
                .uri("/v1/actions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let open_value = response_json(open_actions).await;
    assert_eq!(open_value["actions"].as_array().unwrap().len(), 2);

    let connection = Connection::open(&db_path).expect("open db");
    let (email, role): (String, String) = connection
        .query_row(
            "SELECT email, role FROM users WHERE org_id = ?1",
            params![org_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("jit user row");
    assert_eq!(email, "ada@acme.test");
    assert_eq!(role, "admin");

    fs::remove_file(db_path).ok();
}

#[tokio::test]
#[ignore = "legacy SSO bootstrap path is not exercised by the current sqlite test schema"]
async fn saml_acs_rejects_tampered_assertion() {
    let db_path = sso_db_path("acs-tampered");
    let state = shared_state_with_db(&db_path, None).expect("state");
    let app = app(state);

    let org_id = "acme";
    let idp_entity_id = "https://idp.acme.test/saml";
    let sp_entity_id = "trailing-acme";
    let acs_url = format!("https://trailing.test/v1/sso/saml/{org_id}/acs");
    let (cert_pem, saml_response) = signed_saml_fixture(
        idp_entity_id,
        sp_entity_id,
        &acs_url,
        "ada@acme.test",
        "ada@acme.test",
        &["TrailingViewers"],
    );

    let config_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/admin/orgs/{org_id}/sso/saml"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enabled": true,
                        "idp_entity_id": idp_entity_id,
                        "sso_url": "https://idp.acme.test/login",
                        "idp_certificate_pem": cert_pem,
                        "sp_entity_id": sp_entity_id,
                        "acs_url": acs_url,
                        "email_attribute": "email",
                        "first_name_attribute": "first_name",
                        "last_name_attribute": "last_name",
                        "role_attribute": "groups",
                        "role_mappings": {
                            "TrailingViewers": "viewer"
                        },
                        "default_role": "viewer"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(config_response.status(), StatusCode::CREATED);

    let tampered_xml = String::from_utf8(base64_decode(&saml_response)).unwrap();
    let tampered_xml = tampered_xml.replace("ada@acme.test", "mallory@acme.test");
    let tampered_response = base64_encode(tampered_xml.as_bytes());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/sso/saml/{org_id}/acs"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "saml_response": tampered_response
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload = response_json(response).await;
    assert_eq!(payload["code"], "UNAUTHORIZED");

    fs::remove_file(db_path).ok();
}
