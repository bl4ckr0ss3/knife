//! Stable cursor pagination shared by front ends and operation handlers.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageWindow {
    pub offset: usize,
    pub limit: usize,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl PageWindow {
    pub fn from_args(
        args: &Value,
        total: usize,
        default_limit: usize,
        maximum_limit: usize,
        scope: &str,
    ) -> Result<Self> {
        let maximum_limit = maximum_limit.max(1);
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
            .unwrap_or(default_limit)
            .clamp(1, maximum_limit);
        let offset = match args.get("cursor").and_then(Value::as_str) {
            Some(cursor) => parse_cursor(cursor, scope)?,
            None => 0,
        };
        if offset > total {
            return Err(anyhow!(
                "cursor offset {offset} exceeds the {total}-row result"
            ));
        }
        let next_offset = offset.saturating_add(limit);
        let next_cursor = (next_offset < total).then(|| encode_cursor(next_offset, scope));
        Ok(Self {
            offset,
            limit,
            total,
            next_cursor,
        })
    }
}

fn scope_digest(scope: &str) -> String {
    let digest = Sha256::digest(scope.as_bytes());
    format!("{:x}", digest)[..16].to_string()
}

fn encode_cursor(offset: usize, scope: &str) -> String {
    format!("v1:{offset}:{}", scope_digest(scope))
}

fn parse_cursor(cursor: &str, scope: &str) -> Result<usize> {
    let mut parts = cursor.split(':');
    let version = parts.next();
    let offset = parts.next();
    let digest = parts.next();
    if version != Some("v1") || parts.next().is_some() {
        return Err(anyhow!("invalid cursor"));
    }
    if digest != Some(scope_digest(scope).as_str()) {
        return Err(anyhow!("cursor belongs to a different query"));
    }
    offset
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| anyhow!("invalid cursor offset"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cursors_continue_one_query_and_reject_another() {
        let first = PageWindow::from_args(&json!({"limit": 3}), 8, 2, 5, "functions:all").unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.limit, 3);
        let cursor = first.next_cursor.unwrap();
        let second = PageWindow::from_args(
            &json!({"limit": 3, "cursor": cursor}),
            8,
            2,
            5,
            "functions:all",
        )
        .unwrap();
        assert_eq!(second.offset, 3);
        assert!(
            PageWindow::from_args(&json!({"cursor": cursor}), 8, 2, 5, "functions:named").is_err()
        );
    }

    #[test]
    fn limits_are_nonzero_bounded_and_end_without_a_cursor() {
        let page = PageWindow::from_args(&json!({"limit": 0}), 1, 50, 100, "x").unwrap();
        assert_eq!(page.limit, 1);
        assert!(page.next_cursor.is_none());
    }
}
