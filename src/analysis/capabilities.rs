//! Capability detection from imported/dynamic symbol names. Cross-format: the
//! catalogue mixes Win32 APIs and POSIX/libc names so it works on PE and ELF.
//! Nothing here is malicious alone; clustering is what carries meaning.

use std::collections::BTreeMap;

pub struct ApiFlag {
    pub api: &'static str,
    pub category: &'static str,
    pub why: &'static str,
    pub weight: i32,
}

macro_rules! flag {
    ($api:literal, $cat:literal, $why:literal, $w:literal) => {
        ApiFlag {
            api: $api,
            category: $cat,
            why: $why,
            weight: $w,
        }
    };
}

pub static CATALOG: &[ApiFlag] = &[
    // code injection (Windows)
    flag!(
        "VirtualAllocEx",
        "injection",
        "allocate memory in another process",
        3
    ),
    flag!(
        "WriteProcessMemory",
        "injection",
        "write into another process",
        3
    ),
    flag!("CreateRemoteThread", "injection", "remote thread", 3),
    flag!(
        "NtCreateThreadEx",
        "injection",
        "undocumented remote thread",
        3
    ),
    flag!("QueueUserAPC", "injection", "APC injection", 3),
    flag!("SetWindowsHookExA", "injection", "global hook / inject", 2),
    flag!(
        "NtMapViewOfSection",
        "injection",
        "section mapping (hollowing)",
        2
    ),
    flag!(
        "RtlCreateUserThread",
        "injection",
        "low-level remote thread",
        3
    ),
    // dynamic resolution / evasion
    flag!("LoadLibraryA", "dynamic", "load a DLL at runtime", 1),
    flag!("LoadLibraryW", "dynamic", "load a DLL at runtime", 1),
    flag!("GetProcAddress", "dynamic", "resolve API by name", 1),
    flag!("LdrLoadDll", "dynamic", "low-level DLL load", 2),
    flag!("dlopen", "dynamic", "load a shared object at runtime", 1),
    flag!("dlsym", "dynamic", "resolve a symbol at runtime", 1),
    flag!(
        "VirtualProtect",
        "evasion",
        "change memory protection (RWX)",
        2
    ),
    flag!(
        "VirtualProtectEx",
        "evasion",
        "change protection in another process",
        2
    ),
    flag!("mprotect", "evasion", "change page protection (RWX)", 2),
    // anti-analysis
    flag!("IsDebuggerPresent", "anti-debug", "detect a debugger", 2),
    flag!(
        "CheckRemoteDebuggerPresent",
        "anti-debug",
        "detect a debugger",
        2
    ),
    flag!(
        "NtQueryInformationProcess",
        "anti-debug",
        "query debug flags / PEB",
        2
    ),
    flag!("OutputDebugStringA", "anti-debug", "anti-debug trick", 1),
    flag!("ptrace", "anti-debug", "ptrace self / anti-debug", 2),
    // persistence
    flag!("RegSetValueExA", "persistence", "write a registry value", 1),
    flag!("RegSetValueExW", "persistence", "write a registry value", 1),
    flag!("RegCreateKeyExA", "persistence", "create a registry key", 1),
    flag!("CreateServiceA", "persistence", "install a service", 2),
    flag!("CreateServiceW", "persistence", "install a service", 2),
    // credential / data theft
    flag!("CryptUnprotectData", "theft", "decrypt DPAPI secrets", 3),
    flag!("CredEnumerateA", "theft", "enumerate stored credentials", 2),
    flag!("CredEnumerateW", "theft", "enumerate stored credentials", 2),
    flag!("GetClipboardData", "theft", "read the clipboard", 1),
    // surveillance
    flag!(
        "GetAsyncKeyState",
        "surveillance",
        "poll keyboard (keylogger)",
        2
    ),
    flag!("GetKeyState", "surveillance", "read key state", 1),
    flag!("BitBlt", "surveillance", "screen capture", 1),
    // networking / C2
    flag!("InternetOpenA", "network", "WinINet HTTP client", 1),
    flag!("InternetConnectA", "network", "connect to a host", 1),
    flag!("HttpSendRequestA", "network", "send an HTTP request", 1),
    flag!("WinHttpConnect", "network", "WinHTTP client", 1),
    flag!(
        "URLDownloadToFileA",
        "network",
        "download a file (dropper)",
        3
    ),
    flag!(
        "URLDownloadToFileW",
        "network",
        "download a file (dropper)",
        3
    ),
    flag!("connect", "network", "socket connect", 1),
    flag!("socket", "network", "create a socket", 1),
    flag!("send", "network", "socket send", 1),
    flag!("recv", "network", "socket recv", 1),
    flag!("WSAStartup", "network", "Winsock init", 1),
    // process / execution
    flag!("WinExec", "execution", "run a command", 2),
    flag!("ShellExecuteA", "execution", "launch a program", 1),
    flag!("ShellExecuteExW", "execution", "launch a program", 1),
    flag!("CreateProcessA", "execution", "spawn a process", 1),
    flag!("CreateProcessW", "execution", "spawn a process", 1),
    flag!("system", "execution", "run a shell command", 2),
    flag!("execve", "execution", "replace the process image", 2),
    flag!("fork", "execution", "fork a process", 1),
    // privilege
    flag!(
        "AdjustTokenPrivileges",
        "privilege",
        "enable privileges (SeDebug)",
        2
    ),
    flag!("OpenProcessToken", "privilege", "open a process token", 1),
    flag!("setuid", "privilege", "change user id", 1),
    // destruction / crypto
    flag!("CryptEncrypt", "crypto", "encrypt data (ransomware?)", 1),
    flag!("BCryptEncrypt", "crypto", "encrypt data", 1),
    flag!("EVP_EncryptInit_ex", "crypto", "OpenSSL encryption", 1),
    flag!("DeleteFileA", "destruction", "delete files", 1),
    flag!("unlink", "destruction", "delete files", 1),
];

pub struct Match {
    pub api: String,
    pub category: &'static str,
    pub why: &'static str,
    pub weight: i32,
}

/// One match per flagged symbol, deduped, heaviest first.
pub fn matches<'a>(symbols: impl Iterator<Item = &'a str>) -> Vec<Match> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let set: BTreeMap<&str, &ApiFlag> = CATALOG.iter().map(|f| (f.api, f)).collect();
    for s in symbols {
        // strip a leading underscore that Mach-O / some ABIs prepend
        let name = s.strip_prefix('_').unwrap_or(s);
        if let Some(f) = set.get(name) {
            if seen.insert(f.api) {
                out.push(Match {
                    api: f.api.to_string(),
                    category: f.category,
                    why: f.why,
                    weight: f.weight,
                });
            }
        }
    }
    out.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.category.cmp(b.category)));
    out
}

/// category -> count, for the capability summary line.
pub fn cluster(matches: &[Match]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for hit in matches {
        *m.entry(hit.category).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_and_clusters() {
        let syms = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "IsDebuggerPresent",
            "_socket", // leading underscore (Mach-O style) must still match
            "printf",  // not in catalogue
        ];
        let hits = matches(syms.iter().copied());
        let cats = cluster(&hits);
        assert_eq!(cats.get("injection"), Some(&3));
        assert_eq!(cats.get("anti-debug"), Some(&1));
        assert_eq!(cats.get("network"), Some(&1));
        assert!(hits.iter().all(|h| h.api != "printf"));
    }

    #[test]
    fn dedupes_repeats() {
        let syms = ["socket", "socket", "socket"];
        assert_eq!(matches(syms.iter().copied()).len(), 1);
    }
}
