//! # agent-scope-identity
//!
//! * [`Verifier`]: JWT signature verification against JWKS (OIDC discovery, several issuers,
//!   kid-flood protection). Claims are then mapped by the pure core
//!   ([`agent_scope_core::principal_from_claims`]).
//! * [`Sts`]: a small OAuth 2.0 token service: dev issuer, client credentials and
//!   RFC 8693 token exchange with delegation (`act`) chains. Works next to any IdP.
//! * [`AttributeResolver`]: enrich a principal from a directory before the check.
#![forbid(unsafe_code)]

mod resolver;
mod sts;
mod verifier;

pub use resolver::{enrich, AttributeResolver, HttpResolver, StaticResolver};
pub use sts::{ClientDef, DelegationCheck, Sts, StsConfig, TOKEN_EXCHANGE_GRANT};
pub use verifier::Verifier;

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
