#![no_main]
//! Name and URI normalization must never panic and must be idempotent.
use libfuzzer_sys::fuzz_target;
use warden_core::normalize::{normalize_name, normalize_uri};

fuzz_target!(|s: &str| {
    if let Ok(n) = normalize_name(s) {
        assert_eq!(normalize_name(&n).as_deref(), Ok(n.as_str()));
        assert!(n.is_ascii());
    }
    if let Ok(u) = normalize_uri(s) {
        assert!(!u.contains("/../") && !u.ends_with("/.."));
    }
});
