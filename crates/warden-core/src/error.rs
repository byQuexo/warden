use crate::lint::Finding;

/// Why an [`crate::Engine`] could not be built. An engine is either fully valid or not built at all.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("failed to parse {file}: {message}")]
    Parse { file: &'static str, message: String },
    #[error("policy has {} lint error(s):\n{}", .0.len(), render(.0))]
    Lint(Vec<Finding>),
}

fn render(findings: &[Finding]) -> String {
    findings.iter().map(|f| format!("  - {f}")).collect::<Vec<_>>().join("\n")
}
