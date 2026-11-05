//! JSON Schemas for every config file format, generated from the Rust types that parse them,
//! so editors can validate and autocomplete and the schemas cannot drift from the code.

use std::path::Path;

use schemars::{schema_for, JsonSchema};
use serde_json::{json, Map, Value};

const BASE: &str = "https://raw.githubusercontent.com/byQuexo/warden/main/spec/schema";

/// (file stem, title, schema)
pub fn all() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        ("policy", "Warden policy", of::<warden_core::Policy>()),
        ("catalog", "Warden catalog", catalog()),
        ("identity", "Warden identity", of::<warden_core::IdentityConfig>()),
        ("gateway", "Warden gateway", of::<warden_gateway::config::GatewayConfig>()),
        ("suite", "Warden scenario suite", of::<warden_eval::Suite>()),
        ("lock", "Warden catalog lock", of::<warden_core::Lock>()),
        ("sts", "Warden token service", of::<crate::commands::StsFile>()),
    ]
    .into_iter()
    .map(|(stem, title, mut s)| {
        let o = s.as_object_mut().expect("schema is an object");
        o.insert("$id".into(), json!(format!("{BASE}/{stem}.schema.json")));
        o.insert("title".into(), json!(title));
        (stem, title, s)
    })
    .collect()
}

fn of<T: JsonSchema>() -> Value {
    schema_for!(T).to_value()
}

/// The catalog is parsed by hand (sections keyed by action kind), so its envelope is
/// written here and the entry schema is generated.
fn catalog() -> Value {
    let mut entry = of::<warden_core::CatalogEntry>();
    let o = entry.as_object_mut().expect("schema is an object");
    let mut defs = match o.remove("$defs") {
        Some(Value::Object(d)) => d,
        _ => Map::new(),
    };
    o.remove("$schema");
    o.remove("title");
    defs.insert("CatalogEntry".into(), entry);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "description": "Every action an agent may take, with the scopes it needs. Sections are action kinds (tool, resource, prompt, a2a_skill, or a custom kind); keys are glob patterns.",
        "type": "object",
        "required": ["version"],
        "properties": { "version": { "const": 1 } },
        "additionalProperties": {
            "type": "object",
            "properties": {
                "_normalize": { "enum": ["name", "uri"], "description": "How names in this section are normalized before matching." }
            },
            "additionalProperties": { "$ref": "#/$defs/CatalogEntry" }
        },
        "$defs": defs,
    })
}

pub fn render(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("schema serializes");
    s.push('\n');
    s
}

/// Print one schema, or write all of them to `out`; with `check`, fail if `out` is stale.
pub fn run(name: Option<&str>, out: Option<&Path>, check: bool) -> Result<i32, String> {
    let schemas = all();
    if let Some(dir) = out {
        let mut stale = Vec::new();
        for (stem, _, s) in &schemas {
            let path = dir.join(format!("{stem}.schema.json"));
            let text = render(s);
            if check {
                if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                    stale.push(path.display().to_string());
                }
            } else {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
                eprintln!("wrote {}", path.display());
            }
        }
        if !stale.is_empty() {
            eprintln!("out of date (run `warden schema --out {}`):\n  {}", dir.display(), stale.join("\n  "));
            return Ok(1);
        }
        return Ok(0);
    }
    let names: Vec<&str> = schemas.iter().map(|(n, _, _)| *n).collect();
    let name = name.ok_or_else(|| format!("name a schema ({}) or pass --out DIR", names.join(", ")))?;
    let (_, _, s) =
        schemas.iter().find(|(n, _, _)| *n == name).ok_or_else(|| format!("unknown schema `{name}`; one of: {}", names.join(", ")))?;
    print!("{}", render(s));
    Ok(0)
}
