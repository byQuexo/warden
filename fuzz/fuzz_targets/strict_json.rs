#![no_main]
//! The strict argument parser never panics and agrees with serde_json on valid,
//! duplicate-free input.
use libfuzzer_sys::fuzz_target;
use warden_core::json::{parse_strict, Limits};

fuzz_target!(|s: &str| {
    if let Ok(v) = parse_strict(s, Limits::default()) {
        let plain: serde_json::Value = serde_json::from_str(s).expect("strict-valid JSON is valid JSON");
        assert_eq!(v, plain);
    }
});
