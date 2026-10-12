//! Presentation-neutral operation metadata shared by CLI, TUI, and MCP.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAccess {
    ReadOnly,
    ProjectWrite,
    TargetExecution,
    TargetWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRequirement {
    None,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultMode {
    Inline,
    Paginated,
    BackgroundJob,
}

/// One discoverable capability. The handler remains owned by its subsystem;
/// this descriptor is the stable contract consumed by every front end.
#[derive(Debug, Clone, Serialize)]
pub struct OperationDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub params: Value,
    pub access: OperationAccess,
    pub target: TargetRequirement,
    pub result_mode: ResultMode,
    pub emits_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAvailability {
    pub name: String,
    pub access: OperationAccess,
    pub result_mode: ResultMode,
    pub emits_evidence: bool,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl OperationDescriptor {
    pub fn system_read(
        name: &'static str,
        description: &'static str,
        props: Value,
        required: &[&str],
    ) -> Self {
        let mut operation = Self::read(name, description, props, required);
        operation.target = TargetRequirement::None;
        operation
    }

    pub fn read(
        name: &'static str,
        description: &'static str,
        props: Value,
        required: &[&str],
    ) -> Self {
        Self {
            name,
            description,
            params: json!({
                "type": "object",
                "properties": props,
                "required": required,
            }),
            access: OperationAccess::ReadOnly,
            target: TargetRequirement::Active,
            result_mode: ResultMode::Inline,
            emits_evidence: false,
        }
    }

    pub fn project_write(
        name: &'static str,
        description: &'static str,
        props: Value,
        required: &[&str],
    ) -> Self {
        Self {
            name,
            description,
            params: json!({
                "type": "object",
                "properties": props,
                "required": required,
            }),
            access: OperationAccess::ProjectWrite,
            target: TargetRequirement::Active,
            result_mode: ResultMode::Inline,
            emits_evidence: false,
        }
    }

    pub fn with_evidence(mut self) -> Self {
        self.emits_evidence = true;
        self
    }

    pub fn with_result_mode(mut self, result_mode: ResultMode) -> Self {
        self.result_mode = result_mode;
        self
    }

    /// Require at least one of several equivalent argument names. This keeps
    /// compatibility aliases honest in JSON Schema instead of advertising
    /// every alias as optional and deferring the mistake to dispatch time.
    pub fn with_any_required(mut self, alternatives: &[&str]) -> Self {
        self.params["anyOf"] = Value::Array(
            alternatives
                .iter()
                .map(|name| json!({"required": [name]}))
                .collect(),
        );
        self
    }

    pub fn availability(
        &self,
        available: bool,
        unavailable_reason: Option<String>,
    ) -> OperationAvailability {
        OperationAvailability {
            name: self.name.to_string(),
            access: self.access,
            result_mode: self.result_mode,
            emits_evidence: self.emits_evidence,
            available,
            unavailable_reason,
        }
    }

    pub fn mcp_annotations(&self) -> Value {
        json!({
            "readOnlyHint": self.access == OperationAccess::ReadOnly,
            "destructiveHint": self.access == OperationAccess::TargetWrite,
            "idempotentHint": self.access == OperationAccess::ReadOnly,
            "openWorldHint": self.access == OperationAccess::TargetExecution,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_annotations_follow_access_class() {
        let mut descriptor = OperationDescriptor::read("info", "target info", json!({}), &[]);
        assert_eq!(descriptor.mcp_annotations()["readOnlyHint"], true);
        assert_eq!(descriptor.mcp_annotations()["destructiveHint"], false);
        descriptor.access = OperationAccess::TargetExecution;
        assert_eq!(descriptor.mcp_annotations()["openWorldHint"], true);
        assert_eq!(descriptor.mcp_annotations()["readOnlyHint"], false);

        let mutation = OperationDescriptor::project_write(
            "set_name",
            "set a name",
            json!({"name": {"type": "string"}}),
            &["name"],
        );
        assert_eq!(mutation.access, OperationAccess::ProjectWrite);
        assert_eq!(mutation.mcp_annotations()["readOnlyHint"], false);
        assert_eq!(mutation.mcp_annotations()["destructiveHint"], false);
        assert!(
            OperationDescriptor::read("status", "status", json!({}), &[])
                .with_evidence()
                .emits_evidence
        );
    }

    #[test]
    fn compatibility_aliases_require_at_least_one_spelling() {
        let descriptor = OperationDescriptor::read(
            "inspect",
            "inspect a location",
            json!({"selector": {"type": "string"}, "address": {"type": "string"}}),
            &[],
        )
        .with_any_required(&["selector", "address"]);
        assert_eq!(descriptor.params["required"], json!([]));
        assert_eq!(
            descriptor.params["anyOf"],
            json!([{"required": ["selector"]}, {"required": ["address"]}])
        );
    }
}
