#![no_main]
//! Policy and catalog loading never panics; a policy either loads completely or not at all.
use libfuzzer_sys::fuzz_target;
use warden_core::Engine;

const CATALOG: &str = include_str!("../../examples/devtools/catalog.yaml");

fuzz_target!(|s: &str| {
    let _ = Engine::builder().policy_yaml(s).catalog_yaml(CATALOG).build();
    let _ = Engine::builder().policy_yaml("version: 1\n").catalog_yaml(s).build();
});
