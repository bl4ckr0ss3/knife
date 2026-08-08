```
 ▄ ▄ ▄▄▄  ▄ ▄▄▄▄▄▄▄
 █▄█ █ █  █ █ █▄▄ █▄▄   knife
 █ █ █ █▄ █ █ █▄▄ █▄▄   a reverse engineer's binary swiss-army knife
```

Parse, triage, and disassemble **PE, ELF, and Mach-O** from one small Rust
binary. No runtime, no services, the target is never executed.

```
$ knife suspicious.exe

  suspicious.exe
  PE · x86-64 · program · PE32+

  SUSPICIOUS   risk score 7

§ SIGNALS
  ◆ High-entropy section 'UPX1' (7.91/8) — packed or encrypted +2
  ◆ Only 6 imports with packed sections — resolved at runtime      +2
  ◆ Injection/theft capability in a packed binary                  +2
  ...
```

## What it does

One tool, many jobs — the point of a Swiss-army knife:

| command | what you get |
|---|---|
| `knife FILE` / `knife info FILE` | full triage: verdict, hashes, sections, capabilities, IOCs, entry disasm |
| `knife sections FILE` | sections/segments with per-section entropy bars |
| `knife imports FILE` | imported libs + functions, suspicious APIs flagged inline |
| `knife exports FILE` | exported symbols |
| `knife caps FILE` | capabilities inferred from the symbol surface |
| `knife strings FILE --min N` | ASCII + UTF-16 strings |
| `knife iocs FILE` | URLs, IPs, domains, emails, wallets, reg keys, paths — **defanged** |
| `knife hashes FILE` | MD5 / SHA-1 / SHA-256 + **imphash** |
| `knife dis FILE --count N [--vaddr X\|--off Y]` | x86/x64 disassembly (iced-x86) |
| `knife hex FILE --off O --len L` | hex dump |
| `knife map FILE --buckets N` | whole-file entropy sparkline, packed regions flagged |
| `knife funcs FILE [--by-refs]` | recover functions via control-flow analysis |
| `knife dis FILE --func NAME` | disassemble a whole function with labels + xrefs |
| `knife scan FILE` | crypto constants, packer markers, embedded formats |
| `knife yara RULES FILE` | match YARA rules (RULES = a file or a directory) |
| `knife ls FILE` | archive (.a/.lib) members |

`knife FILE --rules RULES` runs the YARA pass as part of the full report and
folds matches into the verdict.

Add `--json` to any analysis command for machine-readable output.

## Cross-format, one model

`goblin` parses PE/ELF/Mach-O; each is flattened into a single neutral model,
so every command works on every format. Validated on real binaries of all
three: a signed Windows DLL, a stripped RISC-V ELF, and a macOS x86-64 Mach-O.

Disassembly is x86/x64 via `iced-x86`; other architectures are reported as
unsupported rather than guessed at.

## Control-flow analysis

`knife funcs` runs a recursive-descent engine that recovers functions, basic
blocks, a control-flow graph, and cross-references — the backbone of an
interactive disassembler. It seeds from the entry point and every named symbol,
follows calls and branches, splits basic blocks, and counts incoming references.

```
knife funcs sample.exe --by-refs      # busiest functions first
knife dis   sample.exe --func main     # whole function, with loc_ labels,
                                       # resolved call targets, and xrefs-to
```

Everything is in virtual-address space, so the address column, branch operands,
and symbol names all agree. A named symbol marks a function boundary, so the
engine keeps distinct functions apart instead of merging them. Direct calls
resolve to `sub_<addr>` or the symbol name; import-name resolution through the
IAT is the next step. x86/x64 only (disassembly is via iced-x86).

## YARA

`knife yara rules.yar sample` runs YARA rules through
[yara-x](https://github.com/VirusTotal/yara-x), VirusTotal's pure-Rust engine,
so there is no libyara C dependency and the cross-platform build stays clean.
`RULES` may be a single `.yar`/`.yara` file or a directory that is walked
recursively. Each match reports the rule name, tags, metadata, and which
strings hit (with counts). Passing `--rules` to the main report folds matches
into the triage score — a hit is weighted heavily, capped so one noisy ruleset
cannot dominate.

## Constant scanning

`knife scan` fingerprints crypto and structure by their known byte sequences,
so you can tell what a stripped blob is doing without running it: AES S-boxes
(generated at runtime from the GF(2⁸) definition, not hard-coded), SHA-1 /
SHA-256 / MD5 / CRC32 constants (searched in both byte orders), Base64
alphabets, packer markers (UPX, MPRESS), and embedded formats (zip, 7z, gzip,
PNG, PDF, CLR metadata). Embedded PEs are confirmed by walking the DOS→PE
header chain rather than trusting a bare `MZ`.

## Triage philosophy

The verdict is a **transparent additive score** — every point is a named
signal you can read. It weights *concealment and anomaly* (packing, RWX
sections, high-entropy overlays, packer section names, tiny import tables)
above raw *capability*, because a system DLL legitimately exports injection
APIs. Capability clusters bite hardest when they combine with each other or
with packing. It shows what a binary can do and how it is built; it leaves
intent to you.

## Build

```
cargo build --release      # target/release/knife  (~2.5 MB, one file)
```

Needs a recent stable Rust (2021 edition). No system libraries beyond the
platform default.

## Layout

```
src/main.rs              CLI + terminal rendering
src/model.rs             the format-neutral Binary model
src/output.rs            palette + entropy bars
src/formats/             detection + PE / ELF / Mach-O → model (via goblin)
src/analysis/entropy     Shannon entropy + map
src/analysis/hashes      file hashes + imphash
src/analysis/strings     string + IOC extraction, defanging
src/analysis/capabilities cross-format suspicious-symbol catalogue
src/analysis/disasm      iced-x86 disassembly + entry resolution
src/analysis/triage      scoring and the verdict
```

## Notes for the curious

- **The certificate table is not an overlay.** A signed PE stores its
  Authenticode blob at end-of-file, past the last section. Naive overlay
  detection counts that high-entropy blob as an appended payload and flags
  every signed binary. knife reads the certificate data directory and excludes
  that region.
- **imphash** follows the pefile/VirusTotal definition: MD5 of the ordered,
  lowercased `module.function` list with the module extension stripped, so
  values cluster the same families other tools would.
- **Entropy is a hint.** RISC-V compressed code and .NET single-file bundles
  are legitimately dense; the tool surfaces high entropy, it does not convict.

## Licence

MIT
