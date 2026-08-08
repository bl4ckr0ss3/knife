//! YARA rule matching via yara-x (VirusTotal's pure-Rust engine). Rules can be
//! a single file or a directory that is walked for *.yar / *.yara.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

#[derive(Debug, Clone, Serialize)]
pub struct RuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    /// (pattern identifier, number of matches)
    pub patterns: Vec<(String, usize)>,
}

/// Compile every rule file found at `path` (a file or a directory).
pub fn compile(path: &str) -> Result<(Rules, usize)> {
    let p = Path::new(path);
    let mut sources: Vec<(String, String)> = Vec::new();

    if p.is_dir() {
        collect_dir(p, &mut sources)?;
        if sources.is_empty() {
            anyhow::bail!("no .yar / .yara files under {path}");
        }
    } else {
        let text = std::fs::read_to_string(p).with_context(|| format!("cannot read {path}"))?;
        sources.push((path.to_string(), text));
    }

    let count = sources.len();
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    Ok((compile_sources(&refs)?, count))
}

/// Compile one or more (name, source) pairs into a rule set.
pub fn compile_sources(sources: &[(&str, &str)]) -> Result<Rules> {
    let mut compiler = Compiler::new();
    for (name, text) in sources {
        compiler
            .add_source(*text)
            .with_context(|| format!("compiling {name}"))?;
    }
    Ok(compiler.build())
}

fn collect_dir(dir: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yar") | Some("yara")
        ) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push((path.display().to_string(), text));
            }
        }
    }
    Ok(())
}

pub fn scan(rules: &Rules, bytes: &[u8]) -> Result<Vec<RuleMatch>> {
    let mut scanner = Scanner::new(rules);
    let results = scanner.scan(bytes).context("YARA scan failed")?;

    let mut out = Vec::new();
    for rule in results.matching_rules() {
        let meta = rule
            .metadata()
            .map(|(k, v)| (k.to_string(), meta_value(&v)))
            .collect();
        let patterns = rule
            .patterns()
            .filter_map(|p| {
                let n = p.matches().count();
                if n > 0 {
                    Some((p.identifier().to_string(), n))
                } else {
                    None
                }
            })
            .collect();
        out.push(RuleMatch {
            rule: rule.identifier().to_string(),
            namespace: rule.namespace().to_string(),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            meta,
            patterns,
        });
    }
    Ok(out)
}

fn meta_value(v: &yara_x::MetaValue) -> String {
    match v {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
        yara_x::MetaValue::String(s) => s.to_string(),
        yara_x::MetaValue::Bytes(b) => format!("{:?}", b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_and_matches() {
        let src = r#"
            rule Finds_Needle {
                meta:
                    author = "test"
                strings:
                    $a = "n33dle"
                condition:
                    $a
            }
        "#;
        let rules = compile_sources(&[("t", src)]).unwrap();
        let hits = scan(&rules, b"........ n33dle n33dle ........").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "Finds_Needle");
        assert_eq!(hits[0].patterns[0].0, "$a");
        assert_eq!(hits[0].patterns[0].1, 2);
        assert!(hits[0]
            .meta
            .iter()
            .any(|(k, v)| k == "author" && v == "test"));
    }

    #[test]
    fn no_match_is_empty() {
        let rules =
            compile_sources(&[("t", "rule R { strings: $a = \"zzz\" condition: $a }")]).unwrap();
        assert!(scan(&rules, b"aaaa").unwrap().is_empty());
    }

    #[test]
    fn bad_syntax_errors() {
        assert!(compile_sources(&[("t", "rule { this is not yara }")]).is_err());
    }
}
