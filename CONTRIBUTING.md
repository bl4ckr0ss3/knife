# Contributing to knife

Thanks for taking a look. Bug reports, feature ideas, and pull requests are all
welcome.

## Before a pull request

CI runs these on Linux, macOS, and Windows and will fail on any of them:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run them locally first. New analysis logic should come with a unit test; see the
`#[cfg(test)]` modules in `src/analysis/`.

## Layout

```
src/main.rs        CLI and terminal rendering
src/model.rs       the format-neutral Binary model
src/formats/       PE / ELF / Mach-O parsing (via goblin)
src/analysis/      entropy, hashes, strings/IOCs, capabilities, signatures,
                   yara, the CFG engine, disasm, and triage scoring
```

## Scope

knife is a static analyzer: it must never execute the file under analysis. Keep
new features offline and dependency-light. The YARA engine (yara-x) is the one
large dependency, chosen because it is pure Rust and needs no C toolchain.
