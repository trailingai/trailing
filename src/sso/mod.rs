use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::storage::SamlIdpConfig;

const SAML_DEPENDENCY_ERROR_MESSAGE: &str =
    "SAML SSO requires python3 with lxml and cryptography packages installed";
const SAML_DEPENDENCY_CHECK_PYTHON_SCRIPT: &str = "import cryptography\nfrom lxml import etree\n";
const SAML_VALIDATION_PYTHON_SCRIPT: &str = r##"
import base64
import datetime as dt
import json
import sys

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
CLOCK_SKEW_SECONDS = 180


def fail(message):
    print(json.dumps({"ok": False, "error": message}))
    sys.exit(0)


def parse_time(raw):
    if not raw:
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        fail(f"invalid SAML timestamp: {raw}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def digest_for_algorithm(algorithm):
    mapping = {
        "http://www.w3.org/2001/04/xmlenc#sha256": hashes.SHA256,
        "http://www.w3.org/2001/04/xmlenc#sha512": hashes.SHA512,
        "http://www.w3.org/2000/09/xmldsig#sha1": hashes.SHA1,
    }
    factory = mapping.get(algorithm)
    if factory is None:
        fail(f"unsupported digest algorithm: {algorithm}")
    return factory()


def verify_signature(public_key, signature, data, algorithm):
    mapping = {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512,
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1": hashes.SHA1,
    }
    factory = mapping.get(algorithm)
    if factory is None:
        fail(f"unsupported signature algorithm: {algorithm}")
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), factory())
    except Exception as exc:
        fail(f"invalid signature: {exc}")


def first_text(node, path):
    found = node.find(path, namespaces=NS)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def attribute_values(assertion):
    values = {}
    for attribute in assertion.findall(".//saml:AttributeStatement/saml:Attribute", namespaces=NS):
        names = [attribute.get("Name"), attribute.get("FriendlyName")]
        collected = []
        for value in attribute.findall("./saml:AttributeValue", namespaces=NS):
            text = "".join(value.itertext()).strip()
            if text:
                collected.append(text)
        for name in names:
            if name and collected:
                values.setdefault(name, []).extend(collected)
    return values


def require_time_window(not_before, not_on_or_after, label, now):
    if not_before is not None and now + dt.timedelta(seconds=CLOCK_SKEW_SECONDS) < not_before:
        fail(f"{label} is not yet valid")
    if not_on_or_after is not None and now - dt.timedelta(seconds=CLOCK_SKEW_SECONDS) >= not_on_or_after:
        fail(f"{label} has expired")


payload = json.load(sys.stdin)
config = payload["config"]
encoded_response = payload["saml_response"]

try:
    xml_bytes = base64.b64decode(encoded_response)
except Exception as exc:
    fail(f"invalid base64 SAMLResponse: {exc}")

try:
    root = etree.fromstring(xml_bytes)
except Exception as exc:
    fail(f"invalid SAML XML: {exc}")

status_code = root.find(".//samlp:StatusCode", namespaces=NS)
if status_code is not None:
    status_value = status_code.get("Value")
    if status_value not in (None, "urn:oasis:names:tc:SAML:2.0:status:Success"):
        fail(f"unexpected SAML response status: {status_value}")

assertion = root.find(".//saml:Assertion", namespaces=NS)
if assertion is None:
    fail("missing SAML Assertion")

assertion_id = assertion.get("ID")
if not assertion_id:
    fail("assertion is missing ID")

signature = assertion.find("./ds:Signature", namespaces=NS)
if signature is None:
    fail("assertion is missing ds:Signature")

signed_info = signature.find("./ds:SignedInfo", namespaces=NS)
if signed_info is None:
    fail("assertion signature is missing SignedInfo")

reference = signed_info.find("./ds:Reference", namespaces=NS)
if reference is None:
    fail("assertion signature is missing Reference")

reference_uri = (reference.get("URI") or "").strip()
if reference_uri != f"#{assertion_id}":
    fail("signature reference does not match assertion ID")

digest_method = reference.find("./ds:DigestMethod", namespaces=NS)
digest_value = first_text(reference, "./ds:DigestValue")
if digest_method is None or not digest_value:
    fail("signature reference is missing digest data")

signature_method = signed_info.find("./ds:SignatureMethod", namespaces=NS)
signature_value = first_text(signature, "./ds:SignatureValue")
if signature_method is None or not signature_value:
    fail("assertion signature is missing signature value")

certificate = x509.load_pem_x509_certificate(config["idp_certificate_pem"].encode("utf-8"))
public_key = certificate.public_key()

assertion_copy = etree.fromstring(etree.tostring(assertion))
signature_copy = assertion_copy.find("./ds:Signature", namespaces=NS)
if signature_copy is not None:
    assertion_copy.remove(signature_copy)

assertion_c14n = etree.tostring(
    assertion_copy, method="c14n", exclusive=True, with_comments=False
)
digest = hashes.Hash(digest_for_algorithm(digest_method.get("Algorithm")))
digest.update(assertion_c14n)
calculated_digest = base64.b64encode(digest.finalize()).decode("ascii")
if calculated_digest != digest_value:
    fail("assertion digest mismatch")

signed_info_c14n = etree.tostring(
    signed_info, method="c14n", exclusive=True, with_comments=False
)
verify_signature(
    public_key,
    base64.b64decode(signature_value),
    signed_info_c14n,
    signature_method.get("Algorithm"),
)

issuer = first_text(assertion, "./saml:Issuer") or first_text(root, "./saml:Issuer")
if config["idp_entity_id"] and issuer != config["idp_entity_id"]:
    fail("assertion issuer did not match configured IdP entity ID")

audiences = [
    audience.text.strip()
    for audience in assertion.findall(
        ".//saml:AudienceRestriction/saml:Audience", namespaces=NS
    )
    if audience.text and audience.text.strip()
]
if config["sp_entity_id"] and config["sp_entity_id"] not in audiences:
    fail("assertion audience did not match configured SP entity ID")

acs_url = config.get("acs_url") or ""
if acs_url:
    recipients = []
    destination = (root.get("Destination") or "").strip()
    if destination:
        recipients.append(destination)
    for confirmation in assertion.findall(
        ".//saml:SubjectConfirmationData", namespaces=NS
    ):
        recipient = (confirmation.get("Recipient") or "").strip()
        if recipient:
            recipients.append(recipient)
    if recipients and acs_url not in recipients:
        fail("assertion recipient did not match configured ACS URL")

now = dt.datetime.now(dt.timezone.utc)
conditions = assertion.find("./saml:Conditions", namespaces=NS)
if conditions is not None:
    require_time_window(
        parse_time(conditions.get("NotBefore")),
        parse_time(conditions.get("NotOnOrAfter")),
        "assertion conditions",
        now,
    )

for confirmation in assertion.findall(".//saml:SubjectConfirmationData", namespaces=NS):
    require_time_window(
        None,
        parse_time(confirmation.get("NotOnOrAfter")),
        "subject confirmation",
        now,
    )

attributes = attribute_values(assertion)
subject = first_text(assertion, ".//saml:Subject/saml:NameID")
if not subject:
    fail("assertion is missing NameID")

email = None
email_attribute = (config.get("email_attribute") or "").strip()
if email_attribute:
    email_values = attributes.get(email_attribute) or []
    if email_values:
        email = email_values[0]
if not email and "@" in subject:
    email = subject
if not email:
    fail("assertion is missing email attribute")

role_values = []
role_attribute = (config.get("role_attribute") or "").strip()
if role_attribute:
    role_values = attributes.get(role_attribute) or []

first_name = None
first_name_attribute = (config.get("first_name_attribute") or "").strip()
if first_name_attribute:
    first_values = attributes.get(first_name_attribute) or []
    if first_values:
        first_name = first_values[0]

last_name = None
last_name_attribute = (config.get("last_name_attribute") or "").strip()
if last_name_attribute:
    last_values = attributes.get(last_name_attribute) or []
    if last_values:
        last_name = last_values[0]

session_index = None
authn_statement = assertion.find(".//saml:AuthnStatement", namespaces=NS)
if authn_statement is not None:
    session_index = authn_statement.get("SessionIndex")

print(
    json.dumps(
        {
            "ok": True,
            "claims": {
                "issuer": issuer,
                "subject": subject,
                "audience": config["sp_entity_id"],
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "role_values": role_values,
                "session_index": session_index,
            },
        }
    )
)
"##;

static SAML_DEPENDENCY_CHECK: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Debug)]
pub enum SamlError {
    Io(std::io::Error),
    Command(String),
    Json(serde_json::Error),
    DependenciesMissing(String),
    Validation(String),
}

impl std::fmt::Display for SamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Command(message) => write!(f, "{message}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::DependenciesMissing(message) => write!(f, "{message}"),
            Self::Validation(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SamlError {}

impl From<std::io::Error> for SamlError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for SamlError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlAssertionClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role_values: Vec<String>,
    pub session_index: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidationOutput {
    ok: bool,
    error: Option<String>,
    claims: Option<SamlAssertionClaims>,
}

fn missing_saml_dependencies() -> SamlError {
    SamlError::DependenciesMissing(SAML_DEPENDENCY_ERROR_MESSAGE.to_string())
}

pub fn validate_saml_dependencies() -> Result<(), SamlError> {
    match SAML_DEPENDENCY_CHECK.get_or_init(|| {
        let output = Command::new("python3")
            .args(["-c", SAML_DEPENDENCY_CHECK_PYTHON_SCRIPT])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();

        match output {
            Ok(output) if output.status.success() => Ok(()),
            Ok(_) => Err(SAML_DEPENDENCY_ERROR_MESSAGE.to_string()),
            Err(_) => Err(SAML_DEPENDENCY_ERROR_MESSAGE.to_string()),
        }
    }) {
        Ok(()) => Ok(()),
        Err(message) => Err(SamlError::DependenciesMissing(message.clone())),
    }
}

impl SamlError {
    pub fn is_dependency_error(&self) -> bool {
        matches!(self, Self::DependenciesMissing(_))
    }
}

pub fn validate_saml_response(
    encoded_response: &str,
    config: &SamlIdpConfig,
) -> Result<SamlAssertionClaims, SamlError> {
    validate_saml_dependencies()?;

    let mut child = Command::new("python3")
        .args(["-c", SAML_VALIDATION_PYTHON_SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                missing_saml_dependencies()
            } else {
                SamlError::Io(error)
            }
        })?;

    let input = json!({
        "saml_response": encoded_response,
        "config": {
            "idp_entity_id": config.idp_entity_id,
            "idp_certificate_pem": config.idp_certificate_pem,
            "sp_entity_id": config.sp_entity_id,
            "acs_url": config.acs_url,
            "email_attribute": config.email_attribute,
            "first_name_attribute": config.first_name_attribute,
            "last_name_attribute": config.last_name_attribute,
            "role_attribute": config.role_attribute,
        }
    });

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input.to_string().as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ModuleNotFoundError") || stderr.contains("No module named") {
            return Err(missing_saml_dependencies());
        }
        return Err(SamlError::Command(format!(
            "python saml validation failed: {}",
            stderr.trim()
        )));
    }

    let parsed: ValidationOutput = serde_json::from_slice(&output.stdout)?;
    if !parsed.ok {
        return Err(SamlError::Validation(
            parsed
                .error
                .unwrap_or_else(|| "SAML validation failed".to_string()),
        ));
    }

    parsed
        .claims
        .ok_or_else(|| SamlError::Validation("SAML validation returned no claims".to_string()))
}
