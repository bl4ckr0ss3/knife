//! Kernel-driver analysis (`knife drv`): the BYOVD pass.
//!
//! This turns the generic pipeline's output into the questions a driver audit
//! actually asks:
//!   - is this a native-subsystem kernel module at all, and what does it import?
//!   - what devices / symbolic links does it expose (and to whom)?
//!   - which IRP major functions does it dispatch, and where are the handlers?
//!   - what IOCTL codes can a user land in those handlers, and how are they
//!     buffered (METHOD_BUFFERED / DIRECT / NEITHER)?
//!   - which kernel primitives (physical-memory maps, arbitrary R/W, driver
//!     loaders, callbacks) are real, with call sites?
//!
//! The symbolic parts reuse `sinks` so the two halves of an audit agree; the
//! IRP/IOCTL recovery is a linear scan of the entry/handler functions because
//! those are store/cmp patterns, not control flow.

use crate::analysis::engine::{Analysis, Function};
use crate::analysis::sinks::{self, Site};
use crate::model::Binary;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A matching vulnerable/malicious-driver snapshot entry, as reported.
#[derive(Debug, Clone, Serialize)]
pub struct LolHit {
    pub file: String,
    pub vendor: String,
    pub product: String,
    pub category: String,
    pub signer: String,
    pub malicious: bool,
}

// CTL_CODE(DeviceType, Function, Method, Access):
//   31..16 DeviceType, 15..14 Access, 13..2 Function, 1..0 Method
fn decode_ctl(code: u32) -> (u32, u32, u32, u32) {
    let device = (code >> 16) & 0xffff;
    let access = (code >> 14) & 0x3;
    let function = (code >> 2) & 0xfff;
    let method = code & 0x3;
    (device, function, method, access)
}

fn method_name(m: u32) -> &'static str {
    match m {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        _ => "METHOD_NEITHER",
    }
}

fn irp_name(major: u8) -> &'static str {
    crate::analysis::ktypes::irp(major as u64)
}

/// Transport-protocol display name for a dispatch handler.
fn dispatch_name(major: u8) -> &'static str {
    match major {
        0 => "DispatchCreate",
        2 => "DispatchClose",
        3 => "DispatchRead",
        4 => "DispatchWrite",
        14 => "DispatchDeviceControl",
        15 => "DispatchInternalDeviceControl",
        18 => "DispatchCleanup",
        16 => "DispatchShutdown",
        _ => "Dispatch",
    }
}

/// A `; MajorFunction[...] /* IRP_MJ_* */` listing hint, base-correct.
fn slot_hint(major: u8) -> String {
    format!("MajorFunction[{major}] /* {} */", irp_name(major))
}

/// Annotation for IOCTL parameter loads inside a device-control handler: the
/// `_IO_STACK_LOCATION.Parameters.DeviceIoControl` fields a handler actually
/// reads (`IoControlCode` at +0x10, `Type3InputBuffer` at +0x18, ...).
fn ioctl_param_hints(insns: &[(u64, iced_x86::Instruction)], out: &mut BTreeMap<u64, String>) {
    use iced_x86::OpKind;
    let fields = crate::analysis::ktypes::IO_STACK_LOCATION;
    for (ip, i) in insns.iter() {
        let (op, disp) = if i.op0_kind() == OpKind::Memory {
            (i.op1_kind(), i.memory_displacement64())
        } else if i.op1_kind() == OpKind::Memory {
            (i.op0_kind(), i.memory_displacement64())
        } else {
            continue;
        };
        if op == OpKind::Register && !matches!(i.mnemonic(), iced_x86::Mnemonic::Lea) {
            if let Some(fl) = crate::analysis::ktypes::field(fields, disp) {
                out.insert(*ip, fl.name.to_string());
            }
        }
    }
}

/// The functions reachable from `roots` through `call` edges (bounded by the
/// visited set, so huge drivers stay linear in reachable functions).
fn reachable_fns(an: &Analysis, roots: &[u64]) -> BTreeSet<u64> {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<u64> = Vec::new();
    for r in roots {
        if seen.insert(*r) {
            stack.push(*r);
        }
    }
    while let Some(f) = stack.pop() {
        let calls: Vec<u64> = an
            .function_at(f)
            .map(|f| f.calls.clone())
            .unwrap_or_default();
        for c in calls {
            if seen.insert(c) {
                stack.push(c);
            }
        }
    }
    seen
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub name: String,
    pub addr: u64,
    pub wide: bool,
    pub xrefs: usize,
    /// True when a function that references this string also calls a
    /// device-creating API (IoCreateDevice / IoCreateSymbolicLink / ...).
    #[serde(default)]
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IrpHandler {
    pub major: u8,
    pub name: String,
    /// Transport-protocol display name: `DispatchDeviceControl` & friends.
    #[serde(default)]
    pub derived: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioctl {
    pub code: u32,
    pub device_type: u32,
    pub function: u32,
    pub method_code: u32,
    pub method: String,
    pub access: u32,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Primitive {
    pub api: String,
    pub class: String,
    pub severity: u8,
    pub sites: Vec<Site>,
    /// True when at least one call site sits in a function reachable from the
    /// entry point or an IRP dispatch handler, i.e. user mode can plausibly
    /// drive it.
    #[serde(default)]
    pub reachable: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DriverReport {
    pub is_driver: bool,
    pub why: Vec<String>,
    pub module: String,
    pub entry: u64,
    pub entry_label: String,
    /// `DriverEntry` when this is a native driver, else the engine label.
    #[serde(default)]
    pub entry_name: String,
    pub bits: u32,
    pub subsystem: Option<String>,
    /// system kernel modules -> import count (ntoskrnl, hal, ndis, ...)
    pub kernel_imports: BTreeMap<String, usize>,
    /// every other imported module (application-layer names)
    pub app_imports: Vec<String>,
    pub devices: Vec<Device>,
    pub irp: Vec<IrpHandler>,
    pub ioctls: Vec<Ioctl>,
    pub primitives: Vec<Primitive>,
    /// Authenticode signing facts (subjects + thumbprints).
    pub signing: crate::analysis::signing::SigningSummary,
    /// Bundled known-vulnerable-driver matches (loldrivers snapshot).
    pub known_bad: Vec<LolHit>,
    /// Instruction-address -> `; field-name` annotations for the listing
    /// (dispatch-table stores, IOCTL parameter loads). Keyed by engine (VA).
    #[serde(default)]
    pub listing_hints: BTreeMap<u64, String>,
}

/// The kernel catalog, as a name set, so report primitives only from the
/// native-API half of the sink catalogue (user-mode sinks stay out of a
/// driver report).
fn kernel_api_set() -> BTreeSet<&'static str> {
    crate::analysis::ntapi::KERNEL_CATALOG
        .iter()
        .map(|d| d.api)
        .collect()
}

/// Cheap identity check (no engine pass): is this likely a kernel driver, so
/// worth the full `report` walk? Subsystem = native, or a `.sys`/`.drv` name.
pub fn plausibly_a_driver(bin: &Binary) -> bool {
    if bin.subsystem.as_deref() == Some("native") {
        return true;
    }
    std::path::Path::new(&bin.path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("sys") || e.eq_ignore_ascii_case("drv"))
}

/// The `; field-name` listing hints for a driver: dispatch-slot stores and
/// IOCTL parameter-field loads. Lightweight (no sink walk, no reachability) so
/// plain `knife dis --func` and the MCP server can show the same type names
/// the interactive driver pane does without a whole driver audit.
pub fn listing_hints(bin: &Binary, bytes: &[u8], an: &Analysis) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    if bin.bits != 64 {
        return out;
    }
    let base = crate::analysis::engine::display_base(bin);
    let entry_va = bin.entry + base;
    let mut handlers: Vec<(u8, u64)> = Vec::new();
    if let Some(entry_fn) = an.function_at(entry_va) {
        let insns = decode_range(bin, bytes, entry_fn);
        for (store_ip, major, addr) in dispatch_table_stores(&insns) {
            out.insert(store_ip, slot_hint(major));
            handlers.push((major, addr));
        }
        // IOCTL parameter-field hints from each device-control handler.
        for (major, addr) in handlers {
            if major == 14 {
                if let Some(h) = an.function_at(addr) {
                    ioctl_param_hints(&decode_range(bin, bytes, h), &mut out);
                }
            }
        }
    }
    out
}

pub fn report(
    bin: &Binary,
    bytes: &[u8],
    an: &Analysis,
    strings: &BTreeMap<u64, crate::analysis::strings::Located>,
) -> DriverReport {
    let base = crate::analysis::engine::display_base(bin);
    let kernel = kernel_api_set();
    let all: BTreeSet<&str> = crate::analysis::sinks::CATALOG
        .iter()
        .chain(crate::analysis::ntapi::KERNEL_CATALOG.iter())
        .map(|d| d.api)
        .collect();

    let mut why = Vec::new();
    if bin.subsystem.as_deref() == Some("native") {
        why.push("native subsystem".into());
    }
    let ext = std::path::Path::new(&bin.path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("sys") || ext.eq_ignore_ascii_case("drv") {
        why.push(format!(".{ext} extension"));
    }
    let is_driver = !why.is_empty();
    let module = std::path::Path::new(&bin.path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string();
    // All report addresses live in the engine's space (VA), matching `an`
    // lookups: the entry point and every string/key are based so they line up
    // with function headers and xref targets even when image_base is non-zero.
    let entry_va = bin.entry + base;
    let entry_label = an.label(entry_va);

    // Import surface: split system DLLs from app-layer names.
    let mut kernel_imports: BTreeMap<String, usize> = BTreeMap::new();
    let mut app_imports: Vec<String> = Vec::new();
    for lib in &bin.imports {
        let base = lib
            .name
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(&lib.name);
        if crate::analysis::ntapi::is_system_module(base) {
            *kernel_imports.entry(lib.name.clone()).or_default() += lib.functions.len();
        } else {
            app_imports.push(lib.name.clone());
        }
    }
    app_imports.sort();

    // Devices and symbolic links: the strings that name a surface, plus whether
    // anything in the image references them. The string map comes from the
    // caller (already built for the TUI / cmd_drv). Re-extracting it here was
    // a whole extra scan of the file for nothing.
    // A device is "created" when a function that references its name (or the
    // UNICODE_STRING struct that points at it, a few bytes below the payload)
    // also calls a device-creation API, so we can tell the exposed surface
    // from a string that merely happens to match.
    let create_slots: BTreeSet<u64> = an
        .imports
        .iter()
        .filter(|(_, full)| {
            let bare = crate::analysis::thunks::bare_name(full);
            matches!(
                bare,
                "IoCreateDevice"
                    | "IoCreateDeviceSecure"
                    | "IoCreateSymbolicLink"
                    | "IoRegisterDeviceInterface"
            )
        })
        .map(|(slot, _)| *slot)
        .collect();
    let create_callers: BTreeSet<u64> = create_slots
        .iter()
        .flat_map(|slot| {
            an.xrefs_to
                .get(slot)
                .map(|xs| {
                    xs.iter()
                        .filter(|x| x.kind == crate::analysis::engine::XrefKind::Call)
                        .filter_map(|x| an.function_at(x.from))
                        .map(|f| f.addr)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();
    // A device is "created" when a function that references its name (or the
    // UNICODE_STRING struct that points at it, a few bytes below the payload)
    // also calls a device-creation API. Precompute the sorted target addresses
    // of those create calls once, and answer each device with a binary search,
    // so a file that embeds thousands of `\Device\` strings stays linear instead
    // of rescanning every call site per string.
    let create_calls: Vec<u64> = an
        .xrefs_from
        .iter()
        .filter(|(from, _)| {
            an.function_at(**from)
                .is_some_and(|f| create_callers.contains(&f.addr))
        })
        .flat_map(|(_, refs)| refs.iter().map(|r| r.to))
        .collect();
    let mut create_calls = create_calls;
    create_calls.sort_unstable();
    create_calls.dedup();
    let created_near = |va: u64| {
        let lo = va.saturating_sub(0x20);
        let hi = va.saturating_add(0x20);
        let first = create_calls.partition_point(|&t| t < lo);
        create_calls.get(first).is_some_and(|&t| t <= hi)
    };
    let mut devices: Vec<Device> = Vec::new();
    for (va, s) in strings {
        let trimmed = s.text.trim_end_matches('\0');
        if trimmed.starts_with("\\Device\\")
            || trimmed.starts_with("\\DosDevices\\")
            || trimmed.starts_with("\\??\\")
            || trimmed.starts_with("\\\\.\\")
        {
            let refs = an.xrefs_to.get(va).map(Vec::len).unwrap_or(0);
            devices.push(Device {
                name: trimmed.to_string(),
                addr: *va,
                wide: s.wide,
                xrefs: refs,
                created: created_near(*va),
            });
        }
    }
    devices.sort_by(|a, b| b.xrefs.cmp(&a.xrefs).then(a.addr.cmp(&b.addr)));

    // IRP dispatch + IOCTL recovery (linear scans of the relevant functions).
    // Only meaningful for native drivers, and 64-bit: the MajorFunction
    // offsets below are the x64 layouts.
    let mut irp: Vec<IrpHandler> = Vec::new();
    let mut ioctls: Vec<Ioctl> = Vec::new();
    let mut listing_hints: BTreeMap<u64, String> = BTreeMap::new();
    if is_driver && bin.bits == 64 {
        if let Some(entry_fn) = an.function_at(entry_va) {
            let insns = decode_range(bin, bytes, entry_fn);
            for (store_ip, major, addr) in dispatch_table_stores(&insns) {
                irp.push(IrpHandler {
                    major,
                    name: irp_name(major).to_string(),
                    derived: dispatch_name(major).to_string(),
                    addr,
                });
                // `mov [obj+slot], handler` -> what the slot is (base-correct:
                // `major` was resolved against whichever x64 layout the stores
                // agreed on, so name the slot from the major directly).
                listing_hints.insert(store_ip, slot_hint(major));
            }
        }
        // ioctl codes + parameter-field hints from each device-control handler
        for h in &irp {
            if h.major == 14 {
                if let Some(f) = function_containing(an, h.addr) {
                    let insns = decode_range(bin, bytes, f);
                    for (addr, code) in ioctl_compares(&insns) {
                        let (device, function, method, access) = decode_ctl(code);
                        ioctls.push(Ioctl {
                            code,
                            device_type: device,
                            function,
                            method_code: method,
                            method: method_name(method).to_string(),
                            access,
                            addr,
                        });
                    }
                    ioctl_param_hints(&insns, &mut listing_hints);
                }
            }
        }
        irp.sort_by_key(|h| h.major);
        ioctls.sort_by_key(|i| i.code);
    }

    // Primitives: kernel-catalog sinks, with call sites and reachability. The
    // sink walk + reachability BFS is the expensive part of a driver audit; a
    // non-driver (or a 32-bit one, where our dispatch recovery does not apply)
    // has no kernel surface worth walking.
    let primitives: Vec<Primitive> = if is_driver && bin.bits == 64 {
        let roots = std::iter::once(entry_va)
            .chain(irp.iter().map(|h| h.addr))
            .collect::<Vec<_>>();
        let reachable = reachable_fns(an, &roots);
        let mut primitives: Vec<Primitive> = sinks::find(an)
            .into_iter()
            .filter(|h| kernel.contains(h.api.as_str()))
            .map(|h| Primitive {
                reachable: h.sites.iter().any(|s| {
                    an.function_at(s.from)
                        .map(|f| reachable.contains(&f.addr))
                        .unwrap_or(false)
                }),
                api: h.api,
                class: h.class.to_string(),
                severity: h.severity,
                sites: h.sites,
            })
            .collect();
        primitives.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.api.cmp(&b.api)));
        primitives
    } else {
        Vec::new()
    };
    let _ = all;

    let signing = crate::analysis::signing::summarize(bin, bytes);
    let known_bad: Vec<LolHit> =
        crate::analysis::loldrivers::lookup(&crate::analysis::hashes::sha256_hex(bytes))
            .into_iter()
            .map(|e| LolHit {
                file: e.file.clone(),
                vendor: e.vendor.clone(),
                product: e.product.clone(),
                category: e.category.clone(),
                signer: e.signer.clone(),
                malicious: e.is_malicious(),
            })
            .collect();

    let entry_name = if is_driver {
        "DriverEntry".to_string()
    } else {
        entry_label.clone()
    };

    DriverReport {
        is_driver,
        why,
        module,
        entry: entry_va,
        entry_label,
        entry_name,
        bits: bin.bits,
        subsystem: bin.subsystem.clone(),
        kernel_imports,
        app_imports,
        devices,
        irp,
        ioctls,
        primitives,
        signing,
        known_bad,
        listing_hints,
    }
}

fn function_containing(an: &Analysis, addr: u64) -> Option<&Function> {
    an.function_at(addr)
}

/// Decode a function's whole byte range into (ip, instruction) pairs.
fn decode_range(bin: &Binary, bytes: &[u8], f: &Function) -> Vec<(u64, iced_x86::Instruction)> {
    let start = f.addr;
    let end = f
        .blocks
        .iter()
        .map(|b| b.end)
        .max()
        .unwrap_or(start + f.size);
    let Some(off) = crate::analysis::disasm::vaddr_to_off(bin, start) else {
        return Vec::new();
    };
    let len = end.saturating_sub(start);
    let code = &bytes[off as usize..(off as usize + len as usize).min(bytes.len())];
    let mut dec = iced_x86::Decoder::with_ip(64, code, start, iced_x86::DecoderOptions::NONE);
    let mut out = Vec::new();
    while dec.can_decode() {
        let insn = dec.decode();
        out.push((insn.ip(), insn));
    }
    out
}

/// Find `DriverObject->MajorFunction[i] = handler` stores in DriverEntry.
///
/// Pattern: the entry function does `lea rN, [rip+handler]` then
/// `mov [rX + 0x70 + 8*i], rN` where rX holds DriverObject (rcx on entry, or a
/// register it was copied into). Returns (major, handler-address) pairs. This
/// is a heuristic: it only fires on the store shape, never invents handlers.
/// Returns one `(store_ip, major, handler-addr)` per recovered slot store.
fn dispatch_table_stores(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u8, u64)> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let bases = crate::analysis::ktypes::MAJOR_BASES;
    // candidate stores: (store-ip, disp, handler-value)
    let mut cands: Vec<(u64, u64, u64)> = Vec::new();
    let mut reg_value: BTreeMap<Register, u64> = BTreeMap::new();
    let mut obj_regs: Vec<Register> = vec![Register::RCX];
    for (ip, i) in insns.iter() {
        match i.mnemonic() {
            Mnemonic::Lea if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
                if i.memory_base() == Register::RIP && i.is_ip_rel_memory_operand() {
                    // For RIP-relative operands iced reports the absolute target
                    // in `memory_displacement64()` already (ip+len are folded in).
                    reg_value.insert(i.op0_register(), i.memory_displacement64());
                }
            }
            Mnemonic::Mov
                if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register =>
            {
                let d = i.op0_register();
                let s = i.op1_register();
                if let Some(v) = reg_value.get(&s) {
                    reg_value.insert(d, *v);
                }
                if s == Register::RCX && !obj_regs.contains(&d) {
                    obj_regs.push(d);
                }
            }
            Mnemonic::Mov if i.op0_kind() == OpKind::Memory && i.op1_kind() == OpKind::Register => {
                let base = i.memory_base();
                let disp = i.memory_displacement64();
                let in_table = bases.iter().any(|&b| (b..b + 8 * 28).contains(&disp));
                if base != Register::None && obj_regs.contains(&base) && in_table {
                    if let Some(value) = reg_value.get(&i.op1_register()).copied() {
                        cands.push((*ip, disp, value));
                    }
                }
            }
            _ => {}
        }
    }
    // Pick the table base the stores actually agree on; ties go to the newer
    // layout so modern drivers win.
    let best = *bases
        .iter()
        .max_by_key(|&&b| {
            cands
                .iter()
                .filter(|(_, d, _)| (b..b + 8 * 28).contains(d))
                .count()
        })
        .unwrap_or(&bases[0]);
    let mut out: Vec<(u64, u8, u64)> = Vec::new();
    for (ip, disp, value) in cands {
        if (best..best + 8 * 28).contains(&disp) {
            let major = ((disp - best) / 8) as u8;
            if major < 28 {
                out.push((ip, major, value));
            }
        }
    }
    out
}

/// Recover literal IOCTL constant compares inside a handler
/// (`cmp reg, imm32` / `cmp [mem], imm32`), decoded via CTL_CODE.
fn ioctl_compares(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u32)> {
    use iced_x86::{Mnemonic, OpKind};
    let mut out = Vec::new();
    for (ip, i) in insns.iter() {
        if i.mnemonic() == Mnemonic::Cmp {
            let code = match (i.op0_kind(), i.op1_kind()) {
                (OpKind::Register, OpKind::Immediate32) | (OpKind::Memory, OpKind::Immediate32) => {
                    i.immediate32()
                }
                _ => continue,
            };
            if code >= 0x10000 {
                out.push((*ip, code));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::db::Db;
    use crate::formats::fixture;

    fn drive(bin_bytes: Vec<u8>) -> (Binary, Vec<u8>, Analysis) {
        let bin = crate::formats::analyze("fixture.sys", &bin_bytes).unwrap();
        let an = engine::analyze(&bin, &bin_bytes, 200_000, &Db::default());
        (bin, bin_bytes, an)
    }

    fn string_map_for(
        bin: &Binary,
        bytes: &[u8],
    ) -> BTreeMap<u64, crate::analysis::strings::Located> {
        crate::listing::string_map(bin, bytes, crate::analysis::engine::display_base(bin))
    }

    #[test]
    fn the_driver_fixture_reports_a_full_driver() {
        let (bin, bytes, an) = drive(fixture::pe_with_driver());
        let rep = report(&bin, &bytes, &an, &string_map_for(&bin, &bytes));
        assert!(rep.is_driver);
        assert!(
            rep.why.iter().any(|w| w.contains("native")),
            "{:?}",
            rep.why
        );
        assert_eq!(rep.entry, 0x1000);
        // device + symlink surfaced, referenced by DriverEntry code
        assert!(rep
            .devices
            .iter()
            .any(|d| d.name == "\\Device\\Knifelab" && d.xrefs >= 1));
        assert!(rep
            .devices
            .iter()
            .any(|d| d.name == "\\DosDevices\\Knifelab"));
        // Both names are consumed by device-creating APIs in DriverEntry.
        assert!(
            rep.devices.iter().all(|d| d.created),
            "fixture devices are created via IoCreateDevice/IoCreateSymbolicLink"
        );
        // IRP_MJ_DEVICE_CONTROL (14) -> 0x1100
        let dc = rep
            .irp
            .iter()
            .find(|h| h.major == 14)
            .expect("device-control dispatch recovered");
        assert_eq!(dc.addr, 0x1100);
        assert_eq!(dc.derived, "DispatchDeviceControl");
        // Entry is named for a driver, and the store got a type hint.
        assert_eq!(rep.entry_name, "DriverEntry");
        assert!(
            rep.listing_hints
                .values()
                .any(|h| h.contains("MajorFunction[14]")),
            "dispatch store carries a MajorFunction hint: {:?}",
            rep.listing_hints
        );
        // one IOCTL constant in the handler, decoded as device 0x22
        assert!(
            rep.ioctls.iter().any(|i| i.device_type == 0x22),
            "{:?}",
            rep.ioctls
        );
        // primitives from the kernel catalog
        let phys = rep
            .primitives
            .iter()
            .find(|p| p.api == "MmMapIoSpace")
            .expect("physical-mem primitive");
        assert_eq!(phys.class, "physical-mem");
        assert!(!phys.sites.is_empty());
        // The physical-memory map sits inside DispatchDeviceControl, which is
        // a dispatch root, so it must be user-mode reachable.
        assert!(
            phys.reachable,
            "MmMapIoSpace is reached from the IRP handler"
        );
        assert!(rep.primitives.iter().any(|p| p.api == "IoCreateDevice"));
        // The helper at 0x1200 calls KeInitializeMutex but nothing reaches it,
        // so that primitive must be marked unreachable from user mode.
        let hidden = rep
            .primitives
            .iter()
            .find(|p| p.api == "KeInitializeMutex")
            .expect("sync primitive from the unreferenced helper");
        assert!(
            !hidden.reachable,
            "KeInitializeMutex is only called from an orphaned function"
        );
        assert!(rep.kernel_imports.contains_key("ntoskrnl.dll"));
    }

    #[test]
    fn ctl_code_round_trips() {
        // CTL_CODE(0x22, 0x10, METHOD_BUFFERED(0), FILE_ANY_ACCESS(3))
        let code = (0x22u32 << 16) | (3u32 << 14) | (0x10u32 << 2);
        assert_eq!(decode_ctl(code), (0x22, 0x10, 0, 3));
    }

    #[test]
    fn irp_major_names_readables() {
        assert_eq!(irp_name(14), "IRP_MJ_DEVICE_CONTROL");
        assert_eq!(irp_name(0), "IRP_MJ_CREATE");
    }

    #[test]
    fn a_console_exe_is_not_a_driver() {
        let buf = fixture::pe_with_iat_call();
        let bin = crate::formats::analyze("fixture.exe", &buf).unwrap();
        let an = engine::analyze(&bin, &buf, 200_000, &Db::default());
        let rep = report(&bin, &buf, &an, &string_map_for(&bin, &buf));
        assert!(!rep.is_driver);
    }
}
