//! # warden-eval
//!
//! Security evaluation for **your** policy, not just the demo one:
//!
//! * [`scenario`]: hand-written cases in YAML (`expect: { effect, rule, visible }`).
//!   The same files are the Rust ↔ TypeScript conformance vectors.
//! * [`generate`]: attack cases derived from a catalog + policy: scope boundaries,
//!   agent ceilings, delegation edges and depth, missing/mistyped/invisible arguments,
//!   homoglyph names, kill switch, service subjects.
//! * [`mutation`]: remove each rule and check that at least one case notices. A rule no
//!   test notices is a rule nobody verified.
//! * [`report`]: hard gates (`scope_violation`, `unapproved_write`, `delegation_escalation`
//!   must be 0), rule coverage, baseline regression, Markdown/JSON output.
#![forbid(unsafe_code)]

pub mod generate;
pub mod mutation;
pub mod report;
pub mod scenario;

pub use report::{EvalReport, GateConfig};
pub use scenario::{run_case, run_cases, Case, CaseResult, Expect, Suite};
