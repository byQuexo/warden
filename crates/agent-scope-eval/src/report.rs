//! Gates, coverage, baseline comparison and report rendering.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::mutation::Mutant;
use crate::scenario::CaseResult;

#[derive(Clone, Debug, Default)]
pub struct GateConfig {
    /// Every rule must fire in at least one case and not fire in at least one case.
    pub require_rule_coverage: bool,
    /// `case id → "pass" | "fail"` from a previous run.
    pub baseline: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Gate {
    pub name: String,
    pub value: String,
    pub threshold: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct RuleCoverage {
    pub fires: bool,
    pub passes: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvalReport {
    pub policy_version: String,
    pub results: Vec<CaseResult>,
    pub mutants: Option<Vec<Mutant>>,
    pub coverage: BTreeMap<String, RuleCoverage>,
    pub regressions: Vec<String>,
    pub gates: Vec<Gate>,
}

fn count(results: &[CaseResult], kind: &str) -> usize {
    results.iter().filter(|r| r.failure.as_deref() == Some(kind)).count()
}

impl EvalReport {
    pub fn build(
        policy_version: &str,
        // (rule id, can the rule "hold back"? false for `always` conditions)
        rule_ids: &[(String, bool)],
        results: Vec<CaseResult>,
        mutants: Option<Vec<Mutant>>,
        cfg: &GateConfig,
    ) -> Self {
        let mut coverage: BTreeMap<String, RuleCoverage> =
            rule_ids.iter().map(|(r, conditional)| (r.clone(), RuleCoverage { fires: false, passes: !conditional })).collect();
        for r in &results {
            for (rule, outcome) in &r.rules {
                if let Some(c) = coverage.get_mut(rule) {
                    if outcome == "pass" {
                        c.passes = true;
                    } else {
                        c.fires = true;
                    }
                }
            }
        }
        let regressions: Vec<String> = match &cfg.baseline {
            None => vec![],
            Some(b) => results.iter().filter(|r| !r.passed && b.get(&key(r)).map(String::as_str) == Some("pass")).map(key).collect(),
        };

        let zero = |name: &str, n: usize| Gate { name: name.into(), value: n.to_string(), threshold: "0".into(), passed: n == 0 };
        let mut gates = vec![
            zero("scope_violation", count(&results, "scope_violation")),
            zero("unapproved_write", count(&results, "unapproved_write")),
            zero("delegation_escalation", count(&results, "delegation_escalation")),
            zero("failed_cases", results.iter().filter(|r| !r.passed).count()),
            zero("baseline_regressions", regressions.len()),
        ];
        if cfg.require_rule_coverage {
            let covered = coverage.values().filter(|c| c.fires && c.passes).count();
            gates.push(Gate {
                name: "rule_coverage".into(),
                value: format!("{covered}/{}", coverage.len()),
                threshold: "100%".into(),
                passed: covered == coverage.len(),
            });
        }
        if let Some(m) = &mutants {
            let killed = m.iter().filter(|x| x.killed()).count();
            gates.push(Gate {
                name: "mutation_score".into(),
                value: format!("{killed}/{}", m.len()),
                threshold: "100%".into(),
                passed: killed == m.len(),
            });
        }
        Self { policy_version: policy_version.into(), results, mutants, coverage, regressions, gates }
    }

    pub fn passed(&self) -> bool {
        self.gates.iter().all(|g| g.passed)
    }

    pub fn baseline(&self) -> BTreeMap<String, String> {
        self.results.iter().map(|r| (key(r), if r.passed { "pass".into() } else { "fail".into() })).collect()
    }

    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        s.push_str("# agent-scope security evaluation\n\n");
        s.push_str(&format!("Policy version `{}`  \n", self.policy_version));
        s.push_str(&format!(
            "**{passed}/{total} cases passed** — {}\n\n",
            if self.passed() { "all gates green ✅" } else { "gates failed ❌" }
        ));
        s.push_str("| Gate | Value | Threshold | |\n|---|---|---|---|\n");
        for g in &self.gates {
            s.push_str(&format!("| `{}` | {} | {} | {} |\n", g.name, g.value, g.threshold, if g.passed { "✅" } else { "❌" }));
        }
        let mut by_suite: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for r in &self.results {
            let e = by_suite.entry(&r.suite).or_default();
            e.0 += 1;
            if r.passed {
                e.1 += 1;
            }
        }
        s.push_str("\n| Suite | Cases | Passed |\n|---|---|---|\n");
        for (suite, (n, p)) in by_suite {
            s.push_str(&format!("| {suite} | {n} | {p} |\n"));
        }
        if !self.coverage.is_empty() {
            s.push_str("\n### Rule coverage\n\n| Rule | fires | holds back |\n|---|---|---|\n");
            for (rule, c) in &self.coverage {
                let m = |b: bool| if b { "✅" } else { "—" };
                s.push_str(&format!("| `{rule}` | {} | {} |\n", m(c.fires), m(c.passes)));
            }
        }
        if let Some(ms) = &self.mutants {
            s.push_str("\n### Mutants (rule removed)\n\n| Rule | Killed by |\n|---|---|\n");
            for m in ms {
                let by = if m.killed_by.is_empty() {
                    "**survived**".to_string()
                } else {
                    m.killed_by.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                };
                s.push_str(&format!("| `{}` | {by} |\n", m.rule));
            }
        }
        let failures: Vec<&CaseResult> = self.results.iter().filter(|r| !r.passed).collect();
        if !failures.is_empty() {
            s.push_str("\n### Failures\n\n| Case | Expected | Actual | Category |\n|---|---|---|---|\n");
            for r in failures {
                s.push_str(&format!(
                    "| {}/{} | {:?} {} | {} {} | {} |\n",
                    r.suite,
                    r.id,
                    r.expect.effect,
                    r.expect.rule.as_deref().unwrap_or(""),
                    r.actual.effect,
                    r.actual.rule,
                    r.failure.as_deref().unwrap_or("")
                ));
            }
        }
        s
    }
}

fn key(r: &CaseResult) -> String {
    format!("{}/{}", r.suite, r.id)
}
