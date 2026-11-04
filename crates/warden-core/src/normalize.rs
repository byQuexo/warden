//! Normalization of names and URIs before any matching happens.
//!
//! Strategy: **reject, don't repair.** Names must be plain ASCII after NFKC + lowercase,
//! which rules out homoglyph attacks (`crm.updаte_deal` with a Cyrillic `а`) without a
//! confusables table. URIs containing traversal segments or leftover escapes are denied.

use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    #[error("name `{0}` contains characters outside [a-z0-9_.-] or is too long")]
    InvalidName(String),
    #[error("uri `{0}` is not a valid absolute URI")]
    InvalidUri(String),
    #[error("uri `{0}` contains a traversal segment, empty segment or residual escape")]
    UnsafeUri(String),
}

/// NFKC → lowercase → must match `^[a-z0-9][a-z0-9_.-]{0,127}$`.
pub fn normalize_name(raw: &str) -> Result<String, NormalizeError> {
    let n: String = raw.nfkc().collect::<String>().to_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 128
        && n.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(n)
    } else {
        Err(NormalizeError::InvalidName(raw.to_string()))
    }
}

/// Key used to detect look-alike collisions between two valid names (`get_salary` vs `get-salary`).
pub fn collision_key(name: &str) -> String {
    name.replace('-', "_")
}

/// Normalize an absolute URI: lowercase scheme and authority, decode percent-escapes once,
/// and reject `.`/`..` segments, empty segments, backslashes, control characters and any
/// remaining `%` (double encoding).
pub fn normalize_uri(raw: &str) -> Result<String, NormalizeError> {
    let bad = || NormalizeError::InvalidUri(raw.to_string());
    let unsafe_ = || NormalizeError::UnsafeUri(raw.to_string());
    let (scheme, rest) = raw.split_once("://").ok_or_else(bad)?;
    if scheme.is_empty()
        || !scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    {
        return Err(bad());
    }
    let decoded = percent_decode(rest).ok_or_else(unsafe_)?;
    if decoded.contains('%') || decoded.contains('\\') || decoded.chars().any(|c| c.is_control()) {
        return Err(unsafe_());
    }
    let (authority, path) = match decoded.split_once('/') {
        Some((a, p)) => (a.to_string(), Some(p.to_string())),
        None => (decoded.clone(), None),
    };
    // `file:///path` has an empty authority; anything else needs one.
    if authority.is_empty() && path.is_none() {
        return Err(bad());
    }
    let mut out = format!("{}://{}", scheme.to_ascii_lowercase(), authority.to_lowercase());
    if let Some(path) = path {
        let segments: Vec<&str> = path.split('/').collect();
        for (i, seg) in segments.iter().enumerate() {
            let last = i + 1 == segments.len();
            if *seg == "." || *seg == ".." || (seg.is_empty() && !last) {
                return Err(unsafe_());
            }
        }
        out.push('/');
        out.push_str(&path);
    }
    Ok(out)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// True if the string contains control (Cc) or invisible format (Cf) characters,
/// e.g. zero-width spaces or bidi overrides used to smuggle look-alike values.
pub fn has_invisible_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_format_char(c))
}

fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(normalize_name("CRM.Update_Deal").as_deref(), Ok("crm.update_deal"));
        // Fullwidth letters fold to ASCII under NFKC.
        assert_eq!(normalize_name("ｃｒｍ.list").as_deref(), Ok("crm.list"));
        // Cyrillic 'а' (U+0430) is rejected, not folded.
        assert!(normalize_name("crm.upd\u{0430}te_deal").is_err());
        assert!(normalize_name("crm.update deal").is_err());
        assert!(normalize_name("").is_err());
        assert!(normalize_name(".hidden").is_err());
    }

    #[test]
    fn uris() {
        assert_eq!(normalize_uri("DOCS://HR/Policies/a.md").as_deref(), Ok("docs://hr/Policies/a.md"));
        assert!(normalize_uri("docs://sales/../it/runbook").is_err());
        assert!(normalize_uri("docs://sales/%2e%2e/it/runbook").is_err());
        assert!(normalize_uri("docs://sales/%252e%252e/it").is_err());
        assert!(normalize_uri("docs://sales//it").is_err());
        assert!(normalize_uri("docs://sales\\..\\it").is_err());
        assert!(normalize_uri("no-scheme").is_err());
        assert_eq!(normalize_uri("docs://hr/a%20b").as_deref(), Ok("docs://hr/a b"));
        assert_eq!(normalize_uri("file:///workspace/.env").as_deref(), Ok("file:///workspace/.env"));
        assert!(normalize_uri("file:///workspace/../etc/passwd").is_err());
        assert!(normalize_uri("file://").is_err());
    }

    #[test]
    fn invisible() {
        assert!(has_invisible_chars("dach\u{200b}"));
        assert!(has_invisible_chars("a\u{202e}b"));
        assert!(!has_invisible_chars("dach"));
    }
}
