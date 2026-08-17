//! Attack surface: the calls worth auditing first, and where they happen.
//!
//! This is deliberately not the capability catalogue. `capabilities` answers a
//! triage question, "what could this program do to a machine", and weights
//! injection and persistence. A vulnerability researcher is asking something
//! else: "given a bug class, where in this binary would it live". So the
//! entries here are grouped by the mistake they enable rather than by intent,
//! and every one of them is a function that is perfectly normal to call and
//! only interesting because of how easy it is to call wrongly.
//!
//! The output is call sites, not an import list. Knowing that a binary imports
//! `memcpy` is worth nothing; knowing it is reached from 41 places, and which
//! function each one sits in, is where an audit starts.

use crate::analysis::engine::{Analysis, XrefKind};
use serde::Serialize;
use std::collections::BTreeMap;

pub struct SinkDef {
    pub api: &'static str,
    pub class: &'static str,
    /// What goes wrong, phrased as the thing to check at the call site.
    pub note: &'static str,
    /// 3 = no safe usage without external bounds, 2 = safe only with care,
    /// 1 = worth seeing but usually fine.
    pub severity: u8,
}

macro_rules! sink {
    ($api:literal, $class:literal, $note:literal, $sev:literal) => {
        SinkDef {
            api: $api,
            class: $class,
            note: $note,
            severity: $sev,
        }
    };
}

/// Cross-format on purpose: a researcher looking at a Windows service and one
/// looking at a Linux daemon are asking the same question.
pub static CATALOG: &[SinkDef] = &[
    // ── unbounded copies: no length parameter exists at all ──
    sink!(
        "strcpy",
        "memory",
        "no bound; length comes from the source",
        3
    ),
    sink!(
        "strcat",
        "memory",
        "no bound; appends until the source ends",
        3
    ),
    sink!("gets", "memory", "no bound and no way to add one", 3),
    sink!(
        "sprintf",
        "memory",
        "no bound; output size depends on the arguments",
        3
    ),
    sink!(
        "vsprintf",
        "memory",
        "no bound; output size depends on the arguments",
        3
    ),
    sink!("wcscpy", "memory", "no bound; wide-character strcpy", 3),
    sink!("wcscat", "memory", "no bound; wide-character strcat", 3),
    sink!("lstrcpyA", "memory", "no bound; Win32 strcpy", 3),
    sink!("lstrcpyW", "memory", "no bound; Win32 strcpy", 3),
    sink!("lstrcatA", "memory", "no bound; Win32 strcat", 3),
    sink!("lstrcatW", "memory", "no bound; Win32 strcat", 3),
    sink!("StrCpyA", "memory", "no bound; shlwapi strcpy", 3),
    sink!("StrCpyW", "memory", "no bound; shlwapi strcpy", 3),
    // ── bounded, but the bound is easy to compute wrongly ──
    sink!(
        "memcpy",
        "memory",
        "check the length against the destination, not the source",
        2
    ),
    sink!(
        "memmove",
        "memory",
        "check the length against the destination, not the source",
        2
    ),
    sink!(
        "strncpy",
        "memory",
        "does not terminate when the source fills the buffer",
        2
    ),
    sink!(
        "strncat",
        "memory",
        "the bound counts remaining space, not total size",
        2
    ),
    sink!(
        "snprintf",
        "memory",
        "returns the length it wanted, not the length written",
        1
    ),
    sink!(
        "_snprintf",
        "memory",
        "does not terminate on truncation in the MSVC form",
        2
    ),
    sink!(
        "strlcpy",
        "memory",
        "truncation is silent; check the return",
        1
    ),
    sink!(
        "wcsncpy",
        "memory",
        "does not terminate when the source fills the buffer",
        2
    ),
    sink!(
        "StringCchCopyA",
        "memory",
        "bounded, but the count is in characters",
        1
    ),
    sink!(
        "StringCbCopyA",
        "memory",
        "bounded, but the count is in bytes",
        1
    ),
    sink!(
        "RtlCopyMemory",
        "memory",
        "check the length against the destination",
        2
    ),
    sink!(
        "CopyMemory",
        "memory",
        "check the length against the destination",
        2
    ),
    sink!(
        "memset",
        "memory",
        "check the length against the destination",
        1
    ),
    sink!(
        "bcopy",
        "memory",
        "check the length against the destination",
        2
    ),
    // ── stack allocation driven by input ──
    sink!(
        "alloca",
        "stack",
        "attacker-sized allocation moves the stack pointer",
        3
    ),
    sink!(
        "_alloca",
        "stack",
        "attacker-sized allocation moves the stack pointer",
        3
    ),
    sink!(
        "_malloca",
        "stack",
        "falls back to the stack for small sizes",
        2
    ),
    sink!(
        "strdupa",
        "stack",
        "stack allocation sized by the input string",
        3
    ),
    // ── format strings: a non-literal format is a write primitive ──
    sink!(
        "printf",
        "format",
        "a non-literal format string is a read and write primitive",
        2
    ),
    sink!(
        "fprintf",
        "format",
        "a non-literal format string is a read and write primitive",
        2
    ),
    sink!(
        "vprintf",
        "format",
        "a non-literal format string is a read and write primitive",
        2
    ),
    sink!(
        "vfprintf",
        "format",
        "a non-literal format string is a read and write primitive",
        2
    ),
    sink!(
        "syslog",
        "format",
        "a non-literal format string is a read and write primitive",
        2
    ),
    sink!(
        "wsprintfA",
        "format",
        "non-literal format, and no bound either",
        3
    ),
    sink!(
        "wsprintfW",
        "format",
        "non-literal format, and no bound either",
        3
    ),
    // ── command and library execution ──
    sink!(
        "system",
        "exec",
        "the whole argument is a shell command line",
        3
    ),
    sink!(
        "popen",
        "exec",
        "the whole argument is a shell command line",
        3
    ),
    sink!(
        "execl",
        "exec",
        "check who controls the path and the arguments",
        2
    ),
    sink!(
        "execlp",
        "exec",
        "resolves through PATH, so PATH controls the target",
        3
    ),
    sink!(
        "execv",
        "exec",
        "check who controls the path and the arguments",
        2
    ),
    sink!(
        "execvp",
        "exec",
        "resolves through PATH, so PATH controls the target",
        3
    ),
    sink!("WinExec", "exec", "the whole argument is a command line", 3),
    sink!(
        "ShellExecuteA",
        "exec",
        "check who controls the file and parameters",
        2
    ),
    sink!(
        "ShellExecuteW",
        "exec",
        "check who controls the file and parameters",
        2
    ),
    sink!(
        "CreateProcessA",
        "exec",
        "an unquoted path lets a prefix directory win",
        2
    ),
    sink!(
        "CreateProcessW",
        "exec",
        "an unquoted path lets a prefix directory win",
        2
    ),
    sink!(
        "LoadLibraryA",
        "exec",
        "a relative name resolves through the search order",
        2
    ),
    sink!(
        "LoadLibraryW",
        "exec",
        "a relative name resolves through the search order",
        2
    ),
    sink!(
        "dlopen",
        "exec",
        "a relative name resolves through the search path",
        2
    ),
    // ── integer and allocation arithmetic ──
    sink!(
        "malloc",
        "alloc",
        "check the size for overflow before it is computed",
        1
    ),
    sink!(
        "realloc",
        "alloc",
        "on failure the original pointer is still live",
        1
    ),
    sink!(
        "calloc",
        "alloc",
        "multiplies internally, which is the safe part",
        1
    ),
    sink!(
        "HeapAlloc",
        "alloc",
        "check the size for overflow before it is computed",
        1
    ),
    sink!(
        "VirtualAlloc",
        "alloc",
        "check the size and the protection flags",
        1
    ),
    sink!(
        "mmap",
        "alloc",
        "check the size and the protection flags",
        1
    ),
    sink!(
        "atoi",
        "alloc",
        "no error reporting; failure is indistinguishable from zero",
        1
    ),
    sink!(
        "strtol",
        "alloc",
        "check errno, not just the return value",
        1
    ),
    // ── filesystem races and predictable paths ──
    sink!(
        "tmpnam",
        "path",
        "the name is returned before it is created",
        3
    ),
    sink!(
        "tempnam",
        "path",
        "the name is returned before it is created",
        3
    ),
    sink!(
        "mktemp",
        "path",
        "the name is returned before it is created",
        3
    ),
    sink!(
        "GetTempFileNameA",
        "path",
        "predictable name, created separately",
        2
    ),
    sink!(
        "GetTempFileNameW",
        "path",
        "predictable name, created separately",
        2
    ),
    sink!(
        "access",
        "path",
        "the check and the open are separate operations",
        2
    ),
    sink!(
        "stat",
        "path",
        "the check and the open are separate operations",
        1
    ),
    sink!(
        "chmod",
        "path",
        "operates on a path, so the target can be swapped",
        2
    ),
    sink!(
        "chown",
        "path",
        "operates on a path, so the target can be swapped",
        2
    ),
    sink!(
        "symlink",
        "path",
        "check where the link is allowed to point",
        2
    ),
    // ── weak randomness where it is load bearing ──
    sink!(
        "rand",
        "random",
        "predictable; not usable for anything security relevant",
        2
    ),
    sink!(
        "srand",
        "random",
        "predictable seed, often the current time",
        2
    ),
    sink!(
        "random",
        "random",
        "predictable; not usable for anything security relevant",
        2
    ),
    sink!(
        "GetTickCount",
        "random",
        "often used as a seed, and it is guessable",
        1
    ),
    // ── privilege and impersonation, where failure is silent ──
    sink!(
        "setuid",
        "privilege",
        "check the return; dropping privilege can fail",
        2
    ),
    sink!(
        "setgid",
        "privilege",
        "check the return; dropping privilege can fail",
        2
    ),
    sink!(
        "seteuid",
        "privilege",
        "an effective id can be restored again later",
        2
    ),
    sink!(
        "ImpersonateNamedPipeClient",
        "privilege",
        "check the return before trusting the context",
        2
    ),
    sink!(
        "RevertToSelf",
        "privilege",
        "check the return; a failure leaves impersonation active",
        2
    ),
];

/// One call site of one sink.
#[derive(Debug, Clone, Serialize)]
pub struct Site {
    /// Address of the calling instruction.
    pub from: u64,
    /// The function the call sits in, if it was recovered.
    pub in_func: Option<String>,
    /// Offset of the call within that function.
    pub at_off: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub api: String,
    pub class: &'static str,
    pub note: &'static str,
    pub severity: u8,
    /// The address(es) code reaches this function through.
    pub via: Vec<u64>,
    /// True when the function is defined in this binary rather than imported,
    /// which is what a statically linked target looks like.
    pub local: bool,
    pub sites: Vec<Site>,
}

impl Hit {
    /// Present but never reached from recovered code. Worth showing rather than
    /// hiding: it usually means the caller was not recovered, not that the
    /// function is unused.
    pub fn is_unreferenced(&self) -> bool {
        self.sites.is_empty()
    }

    pub fn origin(&self) -> &'static str {
        if self.local {
            "local"
        } else {
            "import"
        }
    }
}

/// Match the binary's imports against the catalogue and attach call sites.
pub fn find(an: &Analysis) -> Vec<Hit> {
    let catalog: BTreeMap<&str, &SinkDef> = CATALOG
        .iter()
        .chain(crate::analysis::ntapi::KERNEL_CATALOG.iter())
        .map(|d| (d.api, d))
        .collect();

    // An API can be reachable through several addresses (a stub and its slot,
    // or the same name imported from two modules), so group by name first.
    let mut by_api: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let mut imported: std::collections::BTreeSet<&'static str> = Default::default();
    for (addr, full) in &an.imports {
        let bare = crate::analysis::thunks::bare_name(full);
        if let Some(def) = lookup(&catalog, bare) {
            by_api.entry(def.api).or_default().push(*addr);
            imported.insert(def.api);
        }
    }
    // Statically linked targets have no import for `strcpy` at all: it is a
    // function in this image. As long as symbols survived, matching defined
    // names finds the same call sites that the dynamic case finds through the
    // PLT, which is what keeps this command useful on a static binary.
    for (addr, name) in &an.names {
        let bare = crate::analysis::thunks::bare_name(name);
        if let Some(def) = lookup(&catalog, bare) {
            let slots = by_api.entry(def.api).or_default();
            if !slots.contains(addr) {
                slots.push(*addr);
            }
        }
    }

    let mut out: Vec<Hit> = by_api
        .into_iter()
        .map(|(api, via)| {
            let def = catalog[api];
            let local = !imported.contains(api);
            let mut sites: Vec<Site> = Vec::new();
            for addr in &via {
                let Some(refs) = an.xrefs_to.get(addr) else {
                    continue;
                };
                for x in refs {
                    // A data reference to an import is the address being taken,
                    // not a call, and it is the call sites we are auditing.
                    if x.kind == XrefKind::Data {
                        continue;
                    }
                    let f = an.function_at(x.from);
                    // A stub jumping through its own slot is the stub's
                    // implementation, not somebody calling the API. Without
                    // this every PLT-routed import reports one phantom site.
                    if f.is_some_and(|f| via.contains(&f.addr)) {
                        continue;
                    }
                    sites.push(Site {
                        from: x.from,
                        in_func: f.map(|f| f.name.clone()),
                        at_off: f.map_or(0, |f| x.from.saturating_sub(f.addr)),
                    });
                }
            }
            sites.sort_by_key(|s| s.from);
            sites.dedup_by_key(|s| s.from);
            Hit {
                api: api.to_string(),
                class: def.class,
                note: def.note,
                severity: def.severity,
                via,
                local,
                sites,
            }
        })
        .collect();

    // Most call sites first within a severity band: that is the order an audit
    // actually works in.
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.sites.len().cmp(&a.sites.len()))
            .then(a.api.cmp(&b.api))
    });
    out
}

/// Look up an API allowing for the decorations different toolchains apply:
/// a leading underscore, and the MSVC secure-CRT `_s` suffix pointing back at
/// the unsafe original.
fn lookup<'a>(catalog: &BTreeMap<&str, &'a SinkDef>, name: &str) -> Option<&'a SinkDef> {
    if let Some(d) = catalog.get(name) {
        return Some(d);
    }
    // `_strcpy`, `__isoc99_sscanf` and friends.
    let trimmed = name.trim_start_matches('_');
    let trimmed = trimmed.strip_prefix("isoc99_").unwrap_or(trimmed);
    if let Some(d) = catalog.get(trimmed) {
        return Some(d);
    }
    // glibc's fortified aliases mean the *checked* variant, which is the safe
    // one, so they are deliberately not matched back to the unsafe entry.
    None
}

/// class -> number of call sites, for the summary line.
pub fn cluster(hits: &[Hit]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for h in hits {
        *m.entry(h.class).or_insert(0) += h.sites.len();
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_no_duplicate_entries() {
        // A duplicate would silently shadow the other's note and severity.
        let mut seen = std::collections::HashSet::new();
        for d in CATALOG {
            assert!(seen.insert(d.api), "duplicate catalogue entry: {}", d.api);
        }
    }

    #[test]
    fn severities_are_in_range() {
        for d in CATALOG {
            assert!(
                (1..=3).contains(&d.severity),
                "{} has severity {}",
                d.api,
                d.severity
            );
        }
    }

    #[test]
    fn lookup_sees_through_toolchain_decoration() {
        let catalog: BTreeMap<&str, &SinkDef> = CATALOG.iter().map(|d| (d.api, d)).collect();
        assert_eq!(lookup(&catalog, "strcpy").map(|d| d.api), Some("strcpy"));
        assert_eq!(lookup(&catalog, "_strcpy").map(|d| d.api), Some("strcpy"));
        assert_eq!(lookup(&catalog, "nonesuch").map(|d| d.api), None);
    }

    #[test]
    fn fortified_variants_are_not_treated_as_the_unsafe_original() {
        // `__strcpy_chk` is the bounds-checked form; reporting it as `strcpy`
        // would flag the mitigation as the bug.
        let catalog: BTreeMap<&str, &SinkDef> = CATALOG.iter().map(|d| (d.api, d)).collect();
        assert_eq!(lookup(&catalog, "__strcpy_chk").map(|d| d.api), None);
        assert_eq!(lookup(&catalog, "__memcpy_chk").map(|d| d.api), None);
    }

    #[test]
    fn a_path_runs_from_the_entry_point_to_the_sink() {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &crate::db::Db::default());

        let stub = an.resolve("strcpy", None);
        let paths: Vec<_> = stub
            .iter()
            .flat_map(|t| an.paths_to(*t, &[bin.entry], 8, true))
            .collect();

        assert!(!paths.is_empty(), "entry should reach strcpy");
        let p = &paths[0];
        assert_eq!(p[0], bin.entry, "the chain starts at the entry point");
        assert!(stub.contains(p.last().unwrap()), "and ends at the sink");
    }

    #[test]
    fn a_strict_search_rejects_a_root_that_cannot_reach_the_target() {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &crate::db::Db::default());

        // An address that calls nothing is not a route to strcpy, and a strict
        // search must say so rather than falling back to "nothing calls it".
        let bogus_root = bin.entry + 0x1000;
        let found: Vec<_> = an
            .resolve("strcpy", None)
            .iter()
            .flat_map(|t| an.paths_to(*t, &[bogus_root], 8, true))
            .collect();
        assert!(found.is_empty(), "no chain starts at an unrelated root");
    }

    #[test]
    fn finds_a_sink_and_its_call_site() {
        // The ELF fixture calls `strcpy` through a PLT stub exactly once.
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &crate::db::Db::default());

        let hits = find(&an);
        let strcpy = hits
            .iter()
            .find(|h| h.api == "strcpy")
            .expect("strcpy should be found as a sink");
        assert_eq!(strcpy.class, "memory");
        assert_eq!(strcpy.severity, 3);
        assert_eq!(strcpy.sites.len(), 1, "one call site in the fixture");
        assert_eq!(strcpy.sites[0].from, bin.entry);
    }
}
