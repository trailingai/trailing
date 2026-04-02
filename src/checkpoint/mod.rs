use std::fmt::{Display, Formatter};

use chrono::{DateTime, SecondsFormat, Utc};
use ecdsa::signature::{Signer, Verifier};
use ed25519_dalek::Signature as Ed25519Signature;
use p256::ecdsa::{
    Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    InvalidKeyId,
    InvalidPrivateKeyLength {
        algorithm: SignatureAlgorithm,
        expected: usize,
        actual: usize,
    },
    InvalidPrivateKey(String),
    InvalidPublicKey(String),
    InvalidSignatureEncoding(String),
}

impl Display for CheckpointError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyId => f.write_str("checkpoint key id must not be empty"),
            Self::InvalidPrivateKeyLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "invalid {algorithm} private key length: expected {expected} bytes, found {actual}"
            ),
            Self::InvalidPrivateKey(message) => write!(f, "{message}"),
            Self::InvalidPublicKey(message) => write!(f, "{message}"),
            Self::InvalidSignatureEncoding(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::EcdsaP256Sha256 => 33,
        }
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::EcdsaP256Sha256 => f.write_str("ecdsa_p256_sha256"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyMetadata {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key: String,
    pub fingerprint: String,
    pub label: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointPayload {
    pub checkpoint_id: String,
    pub created_at: String,
    pub sequence: i64,
    pub entry_id: String,
    pub ledger_root_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointVerification {
    pub checkpoint_hash_valid: bool,
    pub signature_valid: bool,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct CheckpointSigner {
    metadata: SigningKeyMetadata,
    private_key: PrivateKey,
}

#[derive(Debug, Clone)]
enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    EcdsaP256(EcdsaSigningKey),
}

impl CheckpointSigner {
    pub fn from_secret_bytes(
        algorithm: SignatureAlgorithm,
        key_id: impl Into<String>,
        label: Option<String>,
        private_key: &[u8],
        created_at: DateTime<Utc>,
    ) -> Result<Self, CheckpointError> {
        let key_id = key_id.into().trim().to_string();
        if key_id.is_empty() {
            return Err(CheckpointError::InvalidKeyId);
        }

        let (private_key, public_key) = match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
                    CheckpointError::InvalidPrivateKeyLength {
                        algorithm,
                        expected: 32,
                        actual: private_key.len(),
                    }
                })?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
                (
                    PrivateKey::Ed25519(signing_key.clone()),
                    signing_key.verifying_key().to_bytes().to_vec(),
                )
            }
            SignatureAlgorithm::EcdsaP256Sha256 => {
                let key = EcdsaSigningKey::from_slice(private_key).map_err(|_| {
                    CheckpointError::InvalidPrivateKey(format!(
                        "invalid {algorithm} private key bytes"
                    ))
                })?;
                (
                    PrivateKey::EcdsaP256(key.clone()),
                    key.verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                )
            }
        };

        Ok(Self {
            metadata: SigningKeyMetadata {
                key_id,
                algorithm,
                public_key: hex::encode(&public_key),
                fingerprint: fingerprint(&public_key),
                label: label.filter(|value| !value.trim().is_empty()),
                created_at: canonical_timestamp(&created_at),
            },
            private_key,
        })
    }

    pub fn metadata(&self) -> &SigningKeyMetadata {
        &self.metadata
    }

    pub fn sign_checkpoint_hash(&self, checkpoint_hash: &str) -> String {
        match &self.private_key {
            PrivateKey::Ed25519(signing_key) => {
                let signature = signing_key.sign(checkpoint_hash.as_bytes());
                hex::encode(signature.to_bytes())
            }
            PrivateKey::EcdsaP256(signing_key) => {
                let signature: EcdsaSignature = signing_key.sign(checkpoint_hash.as_bytes());
                hex::encode(signature.to_der().as_bytes())
            }
        }
    }
}

pub fn checkpoint_hash(payload: &CheckpointPayload) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trailing-checkpoint-v1");
    hasher.update(payload.checkpoint_id.as_bytes());
    hasher.update(payload.created_at.as_bytes());
    hasher.update(payload.sequence.to_string().as_bytes());
    hasher.update(payload.entry_id.as_bytes());
    hasher.update(payload.ledger_root_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn verify_signed_checkpoint(
    payload: &CheckpointPayload,
    checkpoint_hash_value: &str,
    signature: &str,
    metadata: &SigningKeyMetadata,
) -> Result<CheckpointVerification, CheckpointError> {
    let expected_hash = checkpoint_hash(payload);
    let checkpoint_hash_valid = expected_hash == checkpoint_hash_value;
    let signature_valid = if checkpoint_hash_valid {
        verify_signature(metadata, checkpoint_hash_value, signature)?
    } else {
        false
    };

    Ok(CheckpointVerification {
        checkpoint_hash_valid,
        signature_valid,
        verified: checkpoint_hash_valid && signature_valid,
    })
}

pub fn verify_signature(
    metadata: &SigningKeyMetadata,
    checkpoint_hash_value: &str,
    signature: &str,
) -> Result<bool, CheckpointError> {
    let public_key = hex::decode(&metadata.public_key)
        .map_err(|err| CheckpointError::InvalidPublicKey(err.to_string()))?;
    let signature_bytes = hex::decode(signature)
        .map_err(|err| CheckpointError::InvalidSignatureEncoding(err.to_string()))?;

    match metadata.algorithm {
        SignatureAlgorithm::Ed25519 => {
            let public_key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
                CheckpointError::InvalidPublicKey("invalid ed25519 public key length".to_string())
            })?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
                .map_err(|err| CheckpointError::InvalidPublicKey(err.to_string()))?;
            let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
                CheckpointError::InvalidSignatureEncoding(
                    "invalid ed25519 signature length".to_string(),
                )
            })?;
            let signature = Ed25519Signature::from_bytes(&signature_bytes);
            Ok(verifying_key
                .verify(checkpoint_hash_value.as_bytes(), &signature)
                .is_ok())
        }
        SignatureAlgorithm::EcdsaP256Sha256 => {
            let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&public_key)
                .map_err(|err| CheckpointError::InvalidPublicKey(err.to_string()))?;
            let signature = EcdsaSignature::from_der(&signature_bytes)
                .map_err(|err| CheckpointError::InvalidSignatureEncoding(err.to_string()))?;
            Ok(verifying_key
                .verify(checkpoint_hash_value.as_bytes(), &signature)
                .is_ok())
        }
    }
}

pub fn canonical_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::{
        CheckpointPayload, CheckpointSigner, SignatureAlgorithm, checkpoint_hash,
        verify_signed_checkpoint,
    };

    fn sample_payload() -> CheckpointPayload {
        CheckpointPayload {
            checkpoint_id: "checkpoint-1".to_string(),
            created_at: "2026-03-30T12:00:00.000000000Z".to_string(),
            sequence: 42,
            entry_id: "entry-42".to_string(),
            ledger_root_hash: "abc123".repeat(10) + "ab",
        }
    }

    #[test]
    fn ed25519_checkpoint_signatures_verify() {
        let signer = CheckpointSigner::from_secret_bytes(
            SignatureAlgorithm::Ed25519,
            "audit-key-ed25519",
            Some("primary".to_string()),
            &[7u8; 32],
            chrono::Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap(),
        )
        .expect("create signer");
        let payload = sample_payload();
        let hash = checkpoint_hash(&payload);
        let signature = signer.sign_checkpoint_hash(&hash);

        let verification = verify_signed_checkpoint(&payload, &hash, &signature, signer.metadata())
            .expect("verify checkpoint");

        assert!(verification.verified);
    }

    #[test]
    fn ecdsa_checkpoint_signatures_verify() {
        let signer = CheckpointSigner::from_secret_bytes(
            SignatureAlgorithm::EcdsaP256Sha256,
            "audit-key-ecdsa",
            Some("backup".to_string()),
            &[9u8; 32],
            chrono::Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap(),
        )
        .expect("create signer");
        let payload = sample_payload();
        let hash = checkpoint_hash(&payload);
        let signature = signer.sign_checkpoint_hash(&hash);

        let verification = verify_signed_checkpoint(&payload, &hash, &signature, signer.metadata())
            .expect("verify checkpoint");

        assert!(verification.verified);
    }
}
