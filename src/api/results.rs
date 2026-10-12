//! Bounded in-memory retention for agent-facing operation results.
//!
//! A result reference lets a front end return a concise response now and let a
//! later operation retrieve the exact structured payload without recomputing
//! analysis. The store is deliberately bounded and process-local.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const DEFAULT_RESULT_CAPACITY: usize = 64;
pub const DEFAULT_RESULT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResultId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedResult {
    pub id: ResultId,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_sha256: Option<String>,
    pub payload: Value,
    pub serialized_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultSummary {
    pub id: ResultId,
    pub operation: String,
    pub target_sha256: Option<String>,
    pub serialized_bytes: usize,
}

pub struct ResultStore {
    entries: VecDeque<RetainedResult>,
    capacity: usize,
    maximum_bytes: usize,
    used_bytes: usize,
}

impl Default for ResultStore {
    fn default() -> Self {
        Self::new(DEFAULT_RESULT_CAPACITY, DEFAULT_RESULT_BYTES)
    }
}

impl ResultStore {
    pub fn new(capacity: usize, maximum_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity: capacity.max(1),
            maximum_bytes: maximum_bytes.max(1),
            used_bytes: 0,
        }
    }

    /// Retain a structured result. A payload larger than the entire store is
    /// returned normally by its caller but is not retained.
    pub fn insert(
        &mut self,
        operation: &str,
        target_sha256: Option<&str>,
        payload: Value,
    ) -> Option<ResultId> {
        let encoded = serde_json::to_vec(&payload).ok()?;
        if encoded.len() > self.maximum_bytes {
            return None;
        }

        let mut digest = Sha256::new();
        digest.update(operation.as_bytes());
        digest.update([0]);
        if let Some(target) = target_sha256 {
            digest.update(target.as_bytes());
        }
        digest.update([0]);
        digest.update(&encoded);
        let id = ResultId(format!("result-{:x}", digest.finalize()));

        if self.entries.iter().any(|entry| entry.id == id) {
            return Some(id);
        }
        while self.entries.len() >= self.capacity
            || self.used_bytes.saturating_add(encoded.len()) > self.maximum_bytes
        {
            let removed = self.entries.pop_front()?;
            self.used_bytes = self.used_bytes.saturating_sub(removed.serialized_bytes);
        }
        self.used_bytes += encoded.len();
        self.entries.push_back(RetainedResult {
            id: id.clone(),
            operation: operation.to_string(),
            target_sha256: target_sha256.map(str::to_string),
            payload,
            serialized_bytes: encoded.len(),
        });
        Some(id)
    }

    pub fn get(&self, id: &str) -> Option<&RetainedResult> {
        self.entries.iter().find(|entry| entry.id.0 == id)
    }

    pub fn summaries(&self) -> Vec<ResultSummary> {
        self.entries
            .iter()
            .rev()
            .map(|entry| ResultSummary {
                id: entry.id.clone(),
                operation: entry.operation.clone(),
                target_sha256: entry.target_sha256.clone(),
                serialized_bytes: entry.serialized_bytes,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn references_are_stable_and_retrieve_exact_payloads() {
        let mut store = ResultStore::new(4, 4096);
        let payload = json!({"functions": ["one", "two"]});
        let first = store
            .insert("list_functions", Some("abc"), payload.clone())
            .unwrap();
        let second = store
            .insert("list_functions", Some("abc"), payload.clone())
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&first.0).unwrap().payload, payload);
    }

    #[test]
    fn capacity_and_byte_limits_evict_oldest_results() {
        let mut store = ResultStore::new(2, 4096);
        let one = store.insert("one", None, json!([1])).unwrap();
        let two = store.insert("two", None, json!([2])).unwrap();
        let three = store.insert("three", None, json!([3])).unwrap();
        assert!(store.get(&one.0).is_none());
        assert!(store.get(&two.0).is_some());
        assert!(store.get(&three.0).is_some());

        let mut tiny = ResultStore::new(2, 4);
        assert!(tiny.insert("large", None, json!("too large")).is_none());
        assert!(tiny.is_empty());
    }
}
