use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::sink::{chain_hash, GENESIS};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum VerifyError {
    #[error("{file}:{line}: malformed event: {msg}")]
    Malformed { file: String, line: usize, msg: String },
    #[error("{file}:{line}: sequence gap (expected {expected}, found {found}); events were removed or reordered")]
    SeqGap { file: String, line: usize, expected: u64, found: u64 },
    #[error("{file}:{line}: chain link broken (prev does not match previous hash)")]
    BrokenLink { file: String, line: usize },
    #[error("{file}:{line}: hash mismatch; the event was modified")]
    HashMismatch { file: String, line: usize },
    #[error("{file}:{line}: checkpoint signature invalid; the chain was rewritten or the key is wrong")]
    BadSignature { file: String, line: usize },
    #[error("chain `{chain}`: {events} events not covered by a signed checkpoint (limit {limit})")]
    Unanchored { chain: String, events: u64, limit: u64 },
    #[error("I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct VerifyReport {
    pub chains: BTreeMap<String, ChainReport>,
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct ChainReport {
    pub files: usize,
    pub events: u64,
    pub checkpoints: u64,
    pub unanchored_tail: u64,
}

/// `<chain>-<YYYY-MM-DD>.jsonl` → chain
pub(crate) fn chain_of(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_str()?.strip_suffix(".jsonl")?;
    if name.len() < 12 {
        return None;
    }
    let (chain, date) = name.split_at(name.len() - 11);
    let date = date.strip_prefix('-')?;
    let ok = date.len() == 10 && date.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() });
    ok.then(|| chain.to_string())
}

/// Verify every chain in `dir`. With a public key, checkpoint signatures are checked and
/// at most `max_unanchored` events may follow the last checkpoint.
pub fn verify_dir(dir: &Path, pubkey: Option<&VerifyingKey>, max_unanchored: u64) -> Result<VerifyReport, VerifyError> {
    let mut by_chain: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for e in fs::read_dir(dir).map_err(|e| VerifyError::Io(e.to_string()))? {
        let p = e.map_err(|e| VerifyError::Io(e.to_string()))?.path();
        if let Some(c) = chain_of(&p) {
            by_chain.entry(c).or_default().push(p);
        }
    }
    let mut report = VerifyReport::default();
    for (chain, mut files) in by_chain {
        files.sort();
        let mut r = ChainReport { files: files.len(), ..Default::default() };
        let mut prev = GENESIS.to_string();
        let mut expected = 1u64;
        for f in &files {
            let fname = f.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
            let text = fs::read_to_string(f).map_err(|e| VerifyError::Io(e.to_string()))?;
            for (i, line) in text.lines().enumerate() {
                let ln = i + 1;
                if line.trim().is_empty() {
                    continue;
                }
                let mal = |msg: &str| VerifyError::Malformed { file: fname.clone(), line: ln, msg: msg.into() };
                let v: Value = serde_json::from_str(line).map_err(|e| mal(&e.to_string()))?;
                let Value::Object(mut obj) = v else { return Err(mal("not an object")) };
                let seq = obj.get("seq").and_then(Value::as_u64).ok_or_else(|| mal("missing seq"))?;
                if seq != expected {
                    return Err(VerifyError::SeqGap { file: fname, line: ln, expected, found: seq });
                }
                if obj.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
                    return Err(VerifyError::BrokenLink { file: fname, line: ln });
                }
                let hash = obj.remove("hash").and_then(|h| h.as_str().map(str::to_string)).ok_or_else(|| mal("missing hash"))?;
                if chain_hash(&Value::Object(obj.clone())) != hash {
                    return Err(VerifyError::HashMismatch { file: fname, line: ln });
                }
                if obj.get("event").and_then(Value::as_str) == Some("checkpoint") {
                    if let Some(pk) = pubkey {
                        let head = obj.get("head").and_then(Value::as_str).unwrap_or("");
                        let sig = obj
                            .get("sig")
                            .and_then(Value::as_str)
                            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                            .and_then(|b| Signature::from_slice(&b).ok());
                        let ok = head == prev && sig.is_some_and(|s| pk.verify(head.as_bytes(), &s).is_ok());
                        if !ok {
                            return Err(VerifyError::BadSignature { file: fname, line: ln });
                        }
                    }
                    r.checkpoints += 1;
                    r.unanchored_tail = 0;
                } else {
                    r.unanchored_tail += 1;
                }
                r.events += 1;
                prev = hash;
                expected += 1;
            }
        }
        if pubkey.is_some() && r.unanchored_tail > max_unanchored {
            return Err(VerifyError::Unanchored { chain, events: r.unanchored_tail, limit: max_unanchored });
        }
        report.chains.insert(chain, r);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{AuditSink, JsonlConfig, JsonlSink};
    use crate::{generate_signing_key, signing_key_from_b64, verifying_key_from_b64};
    use serde_json::json;

    fn write_chain(dir: &Path, n: usize) -> VerifyingKey {
        let (sk, pk) = generate_signing_key();
        let sink = JsonlSink::open(JsonlConfig {
            dir: dir.to_path_buf(),
            chain: "gw-1".into(),
            signing_key: Some(signing_key_from_b64(&sk).unwrap()),
            checkpoint_every: 5,
        })
        .unwrap();
        for i in 0..n {
            sink.record("decision", json!({"effect": "allow", "i": i})).unwrap();
        }
        sink.checkpoint().unwrap();
        verifying_key_from_b64(&pk).unwrap()
    }

    fn only_file(dir: &Path) -> PathBuf {
        fs::read_dir(dir).unwrap().next().unwrap().unwrap().path()
    }

    #[test]
    fn intact_chain_verifies() {
        let d = tempfile::tempdir().unwrap();
        let pk = write_chain(d.path(), 12);
        let r = verify_dir(d.path(), Some(&pk), 0).unwrap();
        let c = &r.chains["gw-1"];
        assert_eq!(c.checkpoints, 3);
        assert_eq!(c.unanchored_tail, 0);
    }

    #[test]
    fn detects_deleted_and_modified_lines() {
        let d = tempfile::tempdir().unwrap();
        let pk = write_chain(d.path(), 8);
        let f = only_file(d.path());
        let text = fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        let mut deleted = lines.clone();
        deleted.remove(3);
        fs::write(&f, deleted.join("\n")).unwrap();
        assert!(matches!(verify_dir(d.path(), Some(&pk), 100), Err(VerifyError::SeqGap { line: 4, .. })));

        let modified = text.replacen("\"effect\":\"allow\"", "\"effect\":\"deny\"", 1);
        fs::write(&f, modified).unwrap();
        assert!(matches!(verify_dir(d.path(), Some(&pk), 100), Err(VerifyError::HashMismatch { line: 1, .. })));
    }

    #[test]
    fn detects_full_recomputation() {
        let d = tempfile::tempdir().unwrap();
        let pk = write_chain(d.path(), 6);
        let f = only_file(d.path());
        // Attacker rewrites the first event and recomputes every hash, but cannot re-sign.
        let text = fs::read_to_string(&f).unwrap();
        let mut prev = GENESIS.to_string();
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let mut obj: serde_json::Map<String, Value> = serde_json::from_str(line).unwrap();
            obj.remove("hash");
            if i == 0 {
                obj.insert("effect".into(), json!("deny"));
            }
            if obj.get("event").and_then(Value::as_str) == Some("checkpoint") {
                obj.insert("head".into(), json!(prev.clone()));
            }
            obj.insert("prev".into(), json!(prev.clone()));
            let h = chain_hash(&Value::Object(obj.clone()));
            obj.insert("hash".into(), json!(h.clone()));
            prev = h;
            out.push(Value::Object(obj).to_string());
        }
        fs::write(&f, out.join("\n")).unwrap();
        assert!(verify_dir(d.path(), None, 0).is_ok(), "chain alone looks consistent");
        assert!(matches!(verify_dir(d.path(), Some(&pk), 100), Err(VerifyError::BadSignature { .. })));
    }

    #[test]
    fn resumes_existing_chain() {
        let d = tempfile::tempdir().unwrap();
        let pk = write_chain(d.path(), 3);
        // A second writer with a different key would break verification, so reuse is checked by seq only.
        let sink =
            JsonlSink::open(JsonlConfig { dir: d.path().into(), chain: "gw-1".into(), signing_key: None, checkpoint_every: 100 }).unwrap();
        sink.record("decision", json!({})).unwrap();
        let r = verify_dir(d.path(), Some(&pk), 10).unwrap();
        assert_eq!(r.chains["gw-1"].events, 5);
    }

    #[test]
    fn parses_chain_names() {
        assert_eq!(chain_of(Path::new("gw-1-2026-11-04.jsonl")).as_deref(), Some("gw-1"));
        assert_eq!(chain_of(Path::new("notes.txt")), None);
    }
}
