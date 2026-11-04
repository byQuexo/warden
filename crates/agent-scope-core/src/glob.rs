//! Minimal, deterministic glob matching.
//!
//! * `*`  matches any run of characters **except** the separator
//! * `**` matches any run of characters, separators included
//!
//! Names use `.` as separator (`crm.*`), URIs use `/` (`docs://hr/**`).

/// Returns true if `text` matches `pattern`.
pub fn matches(pattern: &str, text: &str, sep: char) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Iterative DP keeps worst-case time at O(|p| * |t|) with no recursion.
    let (n, m) = (p.len(), t.len());
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[n][m] = true;
    for i in (0..n).rev() {
        let double = p[i] == '*' && i + 1 < n && p[i + 1] == '*';
        for j in (0..=m).rev() {
            dp[i][j] = if double {
                // `**` consumes zero chars (skip both stars) or one arbitrary char.
                dp[i + 2][j] || (j < m && dp[i][j + 1])
            } else if p[i] == '*' {
                dp[i + 1][j] || (j < m && t[j] != sep && dp[i][j + 1])
            } else {
                j < m && p[i] == t[j] && dp[i + 1][j + 1]
            };
        }
        if double {
            // Row i+1 (the second star) is never used as a start position on its own.
            continue;
        }
    }
    dp[0][0]
}

/// True if the pattern contains wildcards.
pub fn is_glob(pattern: &str) -> bool {
    pattern.contains('*')
}

/// Separator used for a given normalization mode.
pub fn separator_for_uri(uri_mode: bool) -> char {
    if uri_mode {
        '/'
    } else {
        '.'
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn single_star_stays_in_segment() {
        assert!(matches("crm.*", "crm.update_deal", '.'));
        assert!(!matches("crm.*", "crm.deals.update", '.'));
        assert!(matches("*.delete_*", "hr.delete_employee", '.'));
        assert!(!matches("*.delete_*", "hr.archive", '.'));
        assert!(matches("*.query", "crm.query", '.'));
    }

    #[test]
    fn double_star_crosses_segments() {
        assert!(matches("docs://hr/**", "docs://hr/a/b/c.md", '/'));
        assert!(matches("docs://hr/**", "docs://hr/", '/'));
        assert!(!matches("docs://hr/**", "docs://it/a", '/'));
        assert!(!matches("docs://hr/*", "docs://hr/a/b", '/'));
    }

    #[test]
    fn literals() {
        assert!(matches("hr.get_salary", "hr.get_salary", '.'));
        assert!(!matches("hr.get_salary", "hr.get_salary2", '.'));
        assert!(matches("*", "", '.'));
    }
}
