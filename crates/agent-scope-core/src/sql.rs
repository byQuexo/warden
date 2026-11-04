//! The `sql` constraint: allow only a single read-only `SELECT` over allow-listed tables.
//!
//! This is defense in depth. The upstream must still connect with a read-only role.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use serde::{Deserialize, Serialize};
use sqlparser::ast::{visit_expressions, visit_relations, visit_statements, Expr, SetExpr, Statement};
use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;

const DEFAULT_FUNCTIONS: &[&str] =
    &["count", "sum", "avg", "min", "max", "lower", "upper", "coalesce", "round", "length", "date_trunc"];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlSpec {
    #[serde(default = "default_dialect")]
    pub dialect: String,
    pub tables_allow: Vec<String>,
    #[serde(default)]
    pub functions_allow: Option<Vec<String>>,
}

fn default_dialect() -> String {
    "generic".into()
}

impl SqlSpec {
    pub fn validate(&self) -> Result<(), String> {
        dialect(&self.dialect).map(|_| ())
    }

    /// `Ok(())` if the statement is acceptable, otherwise the reason.
    pub fn check(&self, sql: &str) -> Result<(), String> {
        let d = dialect(&self.dialect)?;
        let stmts = Parser::parse_sql(d.as_ref(), sql).map_err(|e| format!("unparsable SQL: {e}"))?;
        if stmts.len() != 1 {
            return Err(format!("expected exactly one statement, got {}", stmts.len()));
        }
        let Statement::Query(q) = &stmts[0] else {
            return Err("only SELECT queries are allowed".into());
        };
        if !q.locks.is_empty() {
            return Err("locking clauses (FOR UPDATE/SHARE) are not allowed".into());
        }
        if let SetExpr::Select(s) = q.body.as_ref() {
            if s.into.is_some() {
                return Err("SELECT … INTO is not allowed".into());
            }
        }
        // Nested data-modifying statements (e.g. `WITH x AS (DELETE …)`) show up as extra statements.
        let mut count = 0usize;
        let _ = visit_statements(&stmts, |_s| {
            count += 1;
            ControlFlow::<()>::Continue(())
        });
        if count != 1 {
            return Err("nested statements are not allowed".into());
        }

        let mut allowed: BTreeSet<String> = self.tables_allow.iter().map(|t| t.to_lowercase()).collect();
        if let Some(with) = &q.with {
            for cte in &with.cte_tables {
                allowed.insert(cte.alias.name.value.to_lowercase());
            }
        }
        let flow = visit_relations(&stmts, |rel| {
            let full = rel.to_string().to_lowercase().replace('"', "").replace('`', "");
            let last = full.rsplit('.').next().unwrap_or(&full).to_string();
            if allowed.contains(&full) || allowed.contains(&last) {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(format!("table `{full}` is not allowed"))
            }
        });
        if let ControlFlow::Break(e) = flow {
            return Err(e);
        }

        let functions: BTreeSet<String> = match &self.functions_allow {
            Some(f) => f.iter().map(|x| x.to_lowercase()).collect(),
            None => DEFAULT_FUNCTIONS.iter().map(|s| s.to_string()).collect(),
        };
        let flow = visit_expressions(&stmts, |e| {
            if let Expr::Function(f) = e {
                let name = f.name.to_string().to_lowercase();
                if !functions.contains(&name) {
                    return ControlFlow::Break(format!("function `{name}` is not allowed"));
                }
            }
            ControlFlow::Continue(())
        });
        if let ControlFlow::Break(e) = flow {
            return Err(e);
        }
        Ok(())
    }
}

fn dialect(name: &str) -> Result<Box<dyn Dialect>, String> {
    Ok(match name {
        "generic" => Box::new(GenericDialect {}),
        "postgres" | "postgresql" => Box::new(PostgreSqlDialect {}),
        "mysql" => Box::new(MySqlDialect {}),
        "sqlite" => Box::new(SQLiteDialect {}),
        other => return Err(format!("unknown SQL dialect `{other}`")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SqlSpec {
        SqlSpec { dialect: "postgres".into(), tables_allow: vec!["deals".into(), "accounts".into()], functions_allow: None }
    }

    #[test]
    fn allows_plain_selects() {
        assert!(spec().check("SELECT id, amount FROM deals WHERE amount > 10").is_ok());
        assert!(spec().check("SELECT count(*) FROM deals d JOIN accounts a ON a.id = d.account_id").is_ok());
        assert!(spec().check("WITH big AS (SELECT * FROM deals WHERE amount > 5) SELECT * FROM big").is_ok());
    }

    #[test]
    fn rejects_attacks() {
        let s = spec();
        assert!(s.check("SELECT * FROM deals; DROP TABLE accounts").is_err());
        assert!(s.check("DELETE FROM deals").is_err());
        assert!(s.check("SELECT * FROM users").is_err());
        assert!(s.check("SELECT * FROM deals WHERE id IN (SELECT id FROM users)").is_err());
        assert!(s.check("SELECT pg_sleep(10)").is_err());
        assert!(s.check("SELECT * FROM deals FOR UPDATE").is_err());
        assert!(s.check("SELECT * INTO backup FROM deals").is_err());
        assert!(s.check("WITH x AS (DELETE FROM deals RETURNING *) SELECT * FROM x").is_err());
        assert!(s.check("not sql at all").is_err());
    }
}
