//! Strict JSON parsing for tool arguments.
//!
//! Gateways and upstreams may disagree on how to read `{"a":1,"a":2}` (first vs. last key
//! wins). That disagreement is a policy bypass, so duplicate keys are rejected outright.
//! The value that was checked is exactly the value that gets forwarded.

use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_bytes: 64 * 1024, max_depth: 32 }
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JsonError {
    #[error("payload too large: {0} bytes (limit {1})")]
    TooLarge(usize, usize),
    #[error("invalid JSON: {0}")]
    Invalid(String),
}

/// Parse JSON, rejecting duplicate keys, excessive nesting and oversized payloads.
pub fn parse_strict(input: &str, limits: Limits) -> Result<Value, JsonError> {
    if input.len() > limits.max_bytes {
        return Err(JsonError::TooLarge(input.len(), limits.max_bytes));
    }
    let mut de = serde_json::Deserializer::from_str(input);
    let v = StrictSeed { depth: 0, max_depth: limits.max_depth }
        .deserialize(&mut de)
        .map_err(|e| JsonError::Invalid(e.to_string()))?;
    de.end().map_err(|e| JsonError::Invalid(e.to_string()))?;
    Ok(v)
}

/// Validate an already-parsed value against the size and depth limits.
pub fn check_limits(v: &Value, limits: Limits) -> Result<(), JsonError> {
    fn depth(v: &Value) -> usize {
        match v {
            Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
            Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
            _ => 0,
        }
    }
    let size = v.to_string().len();
    if size > limits.max_bytes {
        return Err(JsonError::TooLarge(size, limits.max_bytes));
    }
    if depth(v) > limits.max_depth {
        return Err(JsonError::Invalid(format!("nesting deeper than {}", limits.max_depth)));
    }
    Ok(())
}

/// Canonical serialization (sorted keys, no whitespace) used for hashing.
pub fn canonical(v: &Value) -> String {
    // serde_json's default Map is a BTreeMap, so keys are already sorted.
    v.to_string()
}

struct StrictSeed {
    depth: usize,
    max_depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictSeed {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= self.max_depth {
            return Err(de::Error::custom(format!("nesting deeper than {}", self.max_depth)));
        }
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(StrictSeed { depth: self.depth + 1, max_depth: self.max_depth })? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= self.max_depth {
            return Err(de::Error::custom(format!("nesting deeper than {}", self.max_depth)));
        }
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key `{key}`")));
            }
            let v = map.next_value_seed(StrictSeed { depth: self.depth + 1, max_depth: self.max_depth })?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(parse_strict(r#"{"tenant":"dach","tenant":"enterprise"}"#, Limits::default()).is_err());
        assert!(parse_strict(r#"{"a":{"b":1,"b":2}}"#, Limits::default()).is_err());
        assert!(parse_strict(r#"{"a":{"b":1,"c":2}}"#, Limits::default()).is_ok());
    }

    #[test]
    fn rejects_deep_nesting_and_large_payloads() {
        let deep = "[".repeat(40) + &"]".repeat(40);
        assert!(parse_strict(&deep, Limits::default()).is_err());
        let big = format!("\"{}\"", "a".repeat(70_000));
        assert!(matches!(parse_strict(&big, Limits::default()), Err(JsonError::TooLarge(..))));
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse_strict(r#"{"a":1} {"a":2}"#, Limits::default()).is_err());
    }
}
