//! Deterministic graph views derived from the analysis engine.
//!
//! The same neutral model feeds terminal text, JSON, and Graphviz DOT so an
//! exported graph never disagrees with the CFG/call edges Knife uses itself.

use crate::analysis::engine::Function;
use iced_x86::FlowControl;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Graph {
    pub kind: &'static str,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    pub id: String,
    pub address: u64,
    pub label: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    pub back: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Graph {
    pub fn add_display_base(&mut self, base: u64) {
        for node in &mut self.nodes {
            node.address = node.address.wrapping_add(base);
        }
    }
}

pub fn cfg(function: &Function) -> Graph {
    let starts: BTreeSet<u64> = function.blocks.iter().map(|block| block.start).collect();
    let nodes = function
        .blocks
        .iter()
        .map(|block| Node {
            id: block_id(block.start),
            address: block.start,
            label: if block.start == function.addr {
                "entry".into()
            } else {
                "block".into()
            },
            kind: if block.start == function.addr {
                "entry"
            } else {
                "block"
            },
            detail: Some(format!(
                "{} instruction{} · {} byte{}",
                block.insns.len(),
                if block.insns.len() == 1 { "" } else { "s" },
                block.end.saturating_sub(block.start),
                if block.end.saturating_sub(block.start) == 1 {
                    ""
                } else {
                    "s"
                }
            )),
        })
        .collect();
    let mut edges = BTreeSet::new();
    for block in &function.blocks {
        let last = block.insns.last();
        let conditional = last.is_some_and(|instruction| {
            instruction.flow == FlowControl::ConditionalBranch && block.succ.len() >= 2
        });
        for successor in &block.succ {
            if starts.contains(successor) {
                edges.insert(Edge {
                    from: block_id(block.start),
                    to: block_id(*successor),
                    kind: if conditional {
                        if last.and_then(|instruction| instruction.target) == Some(*successor) {
                            "true"
                        } else {
                            "false"
                        }
                    } else {
                        "flow"
                    },
                    back: *successor <= block.start,
                });
            }
        }
    }
    Graph {
        kind: "cfg",
        nodes,
        edges: edges.into_iter().collect(),
    }
}

pub fn call_graph(
    functions: &[Function],
    imports: &BTreeMap<u64, String>,
    roots: Option<&BTreeSet<u64>>,
) -> Graph {
    let by_addr: BTreeMap<u64, &Function> = functions
        .iter()
        .map(|function| (function.addr, function))
        .collect();
    let included: BTreeSet<u64> = match roots {
        None => by_addr.keys().copied().collect(),
        Some(roots) => reachable_functions(&by_addr, roots),
    };
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeSet::new();
    for address in &included {
        let Some(function) = by_addr.get(address) else {
            continue;
        };
        nodes.insert(
            *address,
            Node {
                id: function_id(*address),
                address: *address,
                label: function.name.clone(),
                kind: "function",
                detail: Some(format!(
                    "{} byte{} · {} block{}",
                    function.size,
                    if function.size == 1 { "" } else { "s" },
                    function.blocks.len(),
                    if function.blocks.len() == 1 { "" } else { "s" }
                )),
            },
        );
        for target in &function.calls {
            let target_internal = by_addr.contains_key(target);
            if target_internal && !included.contains(target) {
                continue;
            }
            nodes.entry(*target).or_insert_with(|| Node {
                id: function_id(*target),
                address: *target,
                label: imports
                    .get(target)
                    .cloned()
                    .unwrap_or_else(|| format!("sub_{target:x}")),
                kind: if imports.contains_key(target) {
                    "import"
                } else if target_internal {
                    "function"
                } else {
                    "external"
                },
                detail: None,
            });
            edges.insert(Edge {
                from: function_id(*address),
                to: function_id(*target),
                kind: "call",
                back: false,
            });
        }
    }
    Graph {
        kind: "callgraph",
        nodes: nodes.into_values().collect(),
        edges: edges.into_iter().collect(),
    }
}

fn reachable_functions(
    functions: &BTreeMap<u64, &Function>,
    roots: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    let mut reached = BTreeSet::new();
    let mut queue: VecDeque<u64> = roots
        .iter()
        .filter(|root| functions.contains_key(root))
        .copied()
        .collect();
    while let Some(address) = queue.pop_front() {
        if !reached.insert(address) {
            continue;
        }
        if let Some(function) = functions.get(&address) {
            for target in &function.calls {
                if functions.contains_key(target) && !reached.contains(target) {
                    queue.push_back(*target);
                }
            }
        }
    }
    reached
}

pub fn dot(graph: &Graph, title: &str) -> String {
    let mut out = String::new();
    out.push_str("digraph knife {\n");
    out.push_str(&format!(
        "  graph [label=\"{}\", labelloc=t, bgcolor=\"#101419\", fontcolor=\"#d7e3ea\"];\n",
        dot_escape(title)
    ));
    out.push_str("  node [shape=box, style=\"rounded,filled\", fillcolor=\"#18222b\", color=\"#39c6d6\", fontcolor=\"#d7e3ea\", fontname=\"monospace\"];\n");
    out.push_str("  edge [color=\"#39c6d6\", fontcolor=\"#d7e3ea\", fontname=\"monospace\"];\n");
    for node in &graph.nodes {
        let color = match node.kind {
            "entry" => "#e6b450",
            "import" => "#9f7aea",
            "external" => "#718096",
            _ => "#39c6d6",
        };
        let detail = node
            .detail
            .as_ref()
            .map(|detail| format!("\\n{}", dot_escape(detail)))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {} [label=\"{}\\n0x{:x}{}\", color=\"{}\"];\n",
            node.id,
            dot_escape(&node.label),
            node.address,
            detail,
            color
        ));
    }
    for edge in &graph.edges {
        let (color, style) = if edge.back {
            ("#e6b450", ", style=dashed")
        } else {
            ("#39c6d6", "")
        };
        let label = matches!(edge.kind, "true" | "false")
            .then(|| format!(", label=\"{}\"", edge.kind.to_uppercase()))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {} -> {} [color=\"{}\"{}{}];\n",
            edge.from, edge.to, color, style, label
        ));
    }
    out.push_str("}\n");
    out
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

fn function_id(address: u64) -> String {
    format!("n_{address:x}")
}

fn block_id(address: u64) -> String {
    format!("b_{address:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine::{BasicBlock, EngineInsn};

    fn function(address: u64, name: &str, calls: &[u64]) -> Function {
        Function {
            addr: address,
            name: name.into(),
            blocks: Vec::new(),
            size: 8,
            incoming: 0,
            calls: calls.to_vec(),
            named: true,
            tables: Vec::new(),
        }
    }

    #[test]
    fn call_graph_is_deterministic_deduplicated_and_can_be_rooted() {
        let functions = vec![
            function(0x1000, "entry", &[0x2000, 0x3000, 0x2000]),
            function(0x2000, "parse", &[0x4000]),
            function(0x5000, "orphan", &[]),
        ];
        let imports = BTreeMap::from([(0x3000, "KERNEL32!ReadFile".into())]);
        let roots = BTreeSet::from([0x1000]);
        let graph = call_graph(&functions, &imports, Some(&roots));
        assert_eq!(
            graph
                .nodes
                .iter()
                .map(|node| node.address)
                .collect::<Vec<_>>(),
            [0x1000, 0x2000, 0x3000, 0x4000]
        );
        assert_eq!(graph.edges.len(), 3, "duplicate calls collapse to one edge");
        assert!(!graph.nodes.iter().any(|node| node.address == 0x5000));
        assert_eq!(graph.nodes[2].kind, "import");
        assert_eq!(graph.nodes[3].kind, "external");
    }

    #[test]
    fn cfg_marks_backward_edges_and_ignores_non_block_successors() {
        let mut function = function(0x1000, "loop", &[]);
        function.blocks = vec![
            BasicBlock {
                start: 0x1000,
                end: 0x1004,
                insns: Vec::new(),
                succ: vec![0x1010],
            },
            BasicBlock {
                start: 0x1010,
                end: 0x1014,
                insns: Vec::new(),
                succ: vec![0x1000, 0x9999],
            },
        ];
        let graph = cfg(&function);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().any(|edge| edge.back));
        assert!(!graph.edges.iter().any(|edge| edge.to == "b_9999"));
    }

    #[test]
    fn cfg_preserves_true_and_false_branch_semantics() {
        let mut function = function(0x1000, "branch", &[]);
        function.blocks = vec![
            BasicBlock {
                start: 0x1000,
                end: 0x1002,
                insns: vec![EngineInsn::new(
                    0x1000,
                    &[0x74, 0x0e],
                    FlowControl::ConditionalBranch,
                    Some(0x1010),
                    None,
                )],
                succ: vec![0x1002, 0x1010],
            },
            BasicBlock {
                start: 0x1002,
                end: 0x1003,
                insns: Vec::new(),
                succ: Vec::new(),
            },
            BasicBlock {
                start: 0x1010,
                end: 0x1011,
                insns: Vec::new(),
                succ: Vec::new(),
            },
        ];
        let graph = cfg(&function);
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.to == "b_1010" && edge.kind == "true"));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.to == "b_1002" && edge.kind == "false"));
        let rendered = dot(&graph, "branch");
        assert!(rendered.contains("label=\"TRUE\""));
        assert!(rendered.contains("label=\"FALSE\""));
    }

    #[test]
    fn dot_escapes_untrusted_symbol_text() {
        let graph = Graph {
            kind: "callgraph",
            nodes: vec![Node {
                id: "n_1".into(),
                address: 1,
                label: "quoted \"name\"\\tail\nnext".into(),
                kind: "function",
                detail: None,
            }],
            edges: Vec::new(),
        };
        let rendered = dot(&graph, "x\"y");
        assert!(rendered.contains("x\\\"y"));
        assert!(rendered.contains("quoted \\\"name\\\"\\\\tail next"));
        assert_eq!(rendered.matches("digraph").count(), 1);
    }
}
