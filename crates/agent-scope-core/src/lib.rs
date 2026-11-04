//! # agent-scope-core
//!
//! The pure decision engine of agent-scope. It answers one question:
//!
//! > May this **agent**, acting for this **subject**, perform this **action** right now?
//!
//! ```text
//! effective = scopes(subject.roles) ∩ agent.max ∩ token.scopes ∩ ⋂ actor.max (delegation chain)
//! decision  = scope_gate(effective, catalog[action]) → rules (restrict only) → effect
//! ```
//!
//! The crate performs no I/O and reads no clock, so it compiles to
//! `wasm32-unknown-unknown` and gives identical answers in Rust and TypeScript.
//! Every error path ends in [`Effect::Deny`].
#![forbid(unsafe_code)]

pub mod catalog;
pub mod claims;
pub mod constraint;
pub mod engine;
pub mod error;
pub mod glob;
pub mod json;
pub mod lint;
pub mod lock;
pub mod model;
pub mod normalize;
pub mod policy;
pub mod sql;

pub use catalog::{Catalog, CatalogEntry, Sensitivity};
pub use claims::{principal_from_claims, IdentityConfig, IssuerConfig, TokenError};
pub use engine::{CustomConstraint, Engine, EngineBuilder};
pub use error::BuildError;
pub use lint::{Finding, Level};
pub use lock::Lock;
pub use model::{Action, ActionKind, AttrValue, Attrs, Context, Decision, Effect, KillSwitch, Principal, Subject, SubjectKind, TraceStep};
pub use policy::Policy;
