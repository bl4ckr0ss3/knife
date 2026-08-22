//! Kernel-driver analysis: devices, IRP dispatch, the IOCTL surface, and the
//! kernel primitives an attacker can reach through them.
//!
//! This is the BYOVD view. The engine computes all of it already
//! (`driver::report`); the window previously reduced the whole thing to a
//! boolean, which is the difference between knowing a file is a driver and
//! knowing what it lets you do.
//!
//! The report is expensive enough to be worth computing once per target and
//! cheap enough to keep, so it is cached beside the other derived state.

use crate::dto::hex;
use crate::state::AppState;
use reknife::analysis::driver;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct DeviceRow {
    pub name: String,
    pub addr: String,
    pub wide: bool,
    pub xrefs: usize,
    /// The function naming this device also calls a device-creating API, so it
    /// is the driver's own device rather than one it merely mentions.
    pub created: bool,
}

#[derive(Serialize)]
pub struct IrpRow {
    pub major: u8,
    pub name: String,
    /// `DispatchDeviceControl` and friends, when the transport is recognised.
    pub derived: String,
    pub addr: String,
}

#[derive(Serialize)]
pub struct IoctlRow {
    pub code: String,
    pub device_type: String,
    pub function: String,
    pub method: String,
    pub access: u32,
    pub addr: String,
}

#[derive(Serialize)]
pub struct SiteRow {
    pub from: String,
    pub in_func: Option<String>,
    pub at_off: String,
}

#[derive(Serialize)]
pub struct PrimitiveRow {
    pub api: String,
    pub class: String,
    pub severity: u8,
    /// A call site in a function reachable from the entry point or a dispatch
    /// handler: user mode can plausibly drive it.
    pub reachable: bool,
    pub sites: Vec<SiteRow>,
}

#[derive(Serialize)]
pub struct KnownBadRow {
    pub file: String,
    pub vendor: String,
    pub product: String,
    pub category: String,
    pub signer: String,
    pub malicious: bool,
}

#[derive(Serialize)]
pub struct DriverDto {
    pub is_driver: bool,
    pub why: Vec<String>,
    pub module: String,
    pub entry: String,
    pub entry_name: String,
    pub subsystem: Option<String>,
    pub kernel_imports: Vec<(String, usize)>,
    pub app_imports: Vec<String>,
    pub devices: Vec<DeviceRow>,
    pub irp: Vec<IrpRow>,
    pub ioctls: Vec<IoctlRow>,
    pub primitives: Vec<PrimitiveRow>,
    pub known_bad: Vec<KnownBadRow>,
}

/// The driver report for the open target, or `null` when it is not a driver.
///
/// `min_severity` and `reachable_only` mirror the terminal interface's filters:
/// a driver's primitive list is long, and what matters is the part user mode
/// can actually reach.
#[tauri::command]
pub fn driver_report(
    state: State<AppState>,
    min_severity: Option<u8>,
    reachable_only: Option<bool>,
) -> Result<Option<DriverDto>, String> {
    let min_severity = min_severity.unwrap_or(1);
    let reachable_only = reachable_only.unwrap_or(false);
    state
        .read(|l| {
            if !driver::plausibly_a_driver(&l.session.bin) {
                return Ok(None);
            }
            let r = driver::report(&l.session.bin, &l.session.bytes, &l.session.an, &l.strings);
            if !r.is_driver {
                return Ok(None);
            }
            Ok(Some(DriverDto {
                is_driver: r.is_driver,
                why: r.why.clone(),
                module: r.module.clone(),
                entry: hex(r.entry),
                entry_name: r.entry_name.clone(),
                subsystem: r.subsystem.clone(),
                kernel_imports: r
                    .kernel_imports
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect(),
                app_imports: r.app_imports.clone(),
                devices: r
                    .devices
                    .iter()
                    .map(|d| DeviceRow {
                        name: d.name.clone(),
                        addr: hex(d.addr),
                        wide: d.wide,
                        xrefs: d.xrefs,
                        created: d.created,
                    })
                    .collect(),
                irp: r
                    .irp
                    .iter()
                    .map(|h| IrpRow {
                        major: h.major,
                        name: h.name.clone(),
                        derived: h.derived.clone(),
                        addr: hex(h.addr),
                    })
                    .collect(),
                ioctls: r
                    .ioctls
                    .iter()
                    .map(|i| IoctlRow {
                        code: format!("0x{:08x}", i.code),
                        device_type: format!("0x{:x}", i.device_type),
                        function: format!("0x{:x}", i.function),
                        method: i.method.clone(),
                        access: i.access,
                        addr: hex(i.addr),
                    })
                    .collect(),
                primitives: r
                    .primitives
                    .iter()
                    .filter(|p| p.severity >= min_severity)
                    .filter(|p| !reachable_only || p.reachable)
                    .map(|p| PrimitiveRow {
                        api: p.api.clone(),
                        class: p.class.clone(),
                        severity: p.severity,
                        reachable: p.reachable,
                        sites: p
                            .sites
                            .iter()
                            .map(|s| SiteRow {
                                from: hex(s.from),
                                in_func: s.in_func.clone(),
                                at_off: format!("0x{:x}", s.at_off),
                            })
                            .collect(),
                    })
                    .collect(),
                known_bad: r
                    .known_bad
                    .iter()
                    .map(|k| KnownBadRow {
                        file: k.file.clone(),
                        vendor: k.vendor.clone(),
                        product: k.product.clone(),
                        category: k.category.clone(),
                        signer: k.signer.clone(),
                        malicious: k.malicious,
                    })
                    .collect(),
            }))
        })
        .map_err(|e| e.to_string())
}
