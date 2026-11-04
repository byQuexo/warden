//! Mutation testing for policies: remove one rule at a time and re-run the suites.
//! A mutant that no case "kills" points at a rule that is not covered by any scenario.

use serde::Serialize;
use warden_core::{Catalog, Engine, Lock, Policy};

use crate::scenario::{run_cases, Suite};

#[derive(Clone, Debug, Serialize)]
pub struct Mutant {
    pub rule: String,
    pub killed_by: Vec<String>,
}

impl Mutant {
    pub fn killed(&self) -> bool {
        !self.killed_by.is_empty()
    }
}

pub fn mutate(policy: &Policy, catalog: &Catalog, lock: Option<&Lock>, suites: &[Suite]) -> Result<Vec<Mutant>, String> {
    let mut out = Vec::new();
    for i in 0..policy.rules.len() {
        let mut p = policy.clone();
        let removed = p.rules.remove(i);
        let engine = Engine::builder().policy(p).catalog(catalog.clone()).lock(lock.cloned()).build().map_err(|e| e.to_string())?;
        let killed_by =
            suites.iter().flat_map(|s| run_cases(&engine, s)).filter(|r| !r.passed).map(|r| format!("{}/{}", r.suite, r.id)).collect();
        out.push(Mutant { rule: removed.id, killed_by });
    }
    Ok(out)
}
