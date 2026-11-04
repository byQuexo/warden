//! # agent-scope-audit
//!
//! A tamper-evident audit log.
//!
//! * Every event is chained: `hash = sha256(prev || canonical_json(event_without_hash))`.
//! * Every N events (and on demand) a **checkpoint** signs the current head with Ed25519.
//!   A hash chain alone can be recomputed by anyone with write access; a signed checkpoint
//!   cannot be forged without the key.
//! * Arguments are stored as HMAC-SHA256, not plain SHA-256: small values such as
//!   `"department": "sales"` would otherwise be reversible with a dictionary.
//! * One chain per gateway instance, one file per day.
//!
//! The [`AuditSink`] trait is the extension point; a failing sink makes the caller deny.
#![forbid(unsafe_code)]

mod sink;
mod verify;

pub use sink::{args_hmac, AuditError, AuditSink, JsonlConfig, JsonlSink, MemorySink, MultiSink, StdoutSink, TracingSink};
pub use verify::{verify_dir, VerifyError, VerifyReport};

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Generate a new Ed25519 checkpoint key pair, returned as (secret, public) base64.
pub fn generate_signing_key() -> (String, String) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let b64 = base64::engine::general_purpose::STANDARD;
    (b64.encode(sk.to_bytes()), b64.encode(sk.verifying_key().to_bytes()))
}

pub fn signing_key_from_b64(s: &str) -> Result<SigningKey, AuditError> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|e| AuditError::Config(format!("signing key: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| AuditError::Config("signing key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key_from_b64(s: &str) -> Result<VerifyingKey, AuditError> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|e| AuditError::Config(format!("public key: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| AuditError::Config("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| AuditError::Config(format!("public key: {e}")))
}
