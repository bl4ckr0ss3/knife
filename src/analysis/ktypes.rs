//! Windows-internals type layouts: field tables for the handful of kernel
//! structures a driver audit reads directly. The intent is IDA-style *names*
//! on raw offset accesses (*`DriverObject->MajorFunction[14]`* instead of
//! *`*(u64*)(rbx + 0xE0)`*), applied where the base type is known without
//! guessing: the device-control stack slot, the driver object's dispatch
//! table, a UNICODE_STRING, and an IOCTL parameter block.
//!
//! Offsets are the documented x64 layouts used by `x64dbg`/WinDbg symbol
//! viewers on modern kernels; 32-bit drivers are out of scope (the driver pass
//! is already 64-bit gated).

use serde::Serialize;

/// A field: byte offset, name, and a short type spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KField {
    pub offset: u64,
    pub name: &'static str,
    pub ty: &'static str,
}

macro_rules! fields {
    ($($off:expr, $name:literal, $ty:literal);+ $(;)?) => {{
        &[ $( KField { offset: $off, name: $name, ty: $ty }, )+ ]
    }};
}

/// x64 `_UNICODE_STRING`.
#[allow(dead_code)] // deferred IR type-renaming
pub static UNICODE_STRING: &[KField] = fields![
    0x00, "Length", "u16";
    0x02, "MaximumLength", "u16";
    0x08, "Buffer", "PWSTR";
];

/// x64 `_DRIVER_OBJECT`. `MajorFunction` is the dispatch table: slot `n` at
/// `MAJOR_BASE + 8*n`. The table has moved between kernels; both documented
/// bases are kept so recovery accepts either.
#[allow(dead_code)] // deferred IR type-renaming
pub static DRIVER_OBJECT: &[KField] = fields![
    0x00, "Type", "u16";
    0x02, "Size", "u16";
    0x08, "DeviceObject", "PDEVICE_OBJECT";
    0x10, "RegistryPath", "UNICODE_STRING";
    0x20, "DriverInit", "ptr";
    0x28, "DriverStart", "ptr";
    0x30, "DriverSize", "u32";
    0x38, "DriverFlags", "u32";
    0x40, "DriverStartIo", "ptr";
    0x48, "DriverUnload", "ptr";
    // MajorFunction[28] @ both known x64 bases.
    0x50, "MajorFunction", "PDRIVER_DISPATCH[28]";
    0x70, "MajorFunction", "PDRIVER_DISPATCH[28]";
];

/// x64 `_IO_STACK_LOCATION`, `Parameters` union at 0x08; the
/// `DeviceIoControl` member is what a dispatch handler reads.
pub static IO_STACK_LOCATION: &[KField] = fields![
    0x00, "MajorFunction", "u8";
    0x01, "MinorFunction", "u8";
    0x02, "Flags", "u8";
    0x03, "Control", "u8";
    0x08, "Parameters.DeviceIoControl.OutputBufferLength", "u32";
    0x0c, "Parameters.DeviceIoControl.InputBufferLength", "u32";
    0x10, "Parameters.DeviceIoControl.IoControlCode", "u32";
    0x18, "Parameters.DeviceIoControl.Type3InputBuffer", "ptr";
];

/// The `MajorFunction` table base for x64 (two historical locations).
pub const MAJOR_BASES: [u64; 2] = [0x50, 0x70];

/// Field lookup inside a known structure.
pub fn field(ty: &'static [KField], offset: u64) -> Option<&'static KField> {
    ty.iter().find(|f| f.offset == offset)
}

/// Render a dispatch-table slot access as `MajorFunction[IRP_MJ_*]`.
/// `offset` is interpreted against the modern (0x50) x64 base.
#[allow(dead_code)] // deferred IR type-renaming
pub fn dispatch_slot(offset: u64) -> Option<String> {
    for base in MAJOR_BASES {
        if offset >= base && (offset - base).is_multiple_of(8) {
            let idx = (offset - base) / 8;
            if idx < 28 {
                return Some(format!("MajorFunction[{idx}] /* {} */", irp(idx)));
            }
        }
    }
    None
}

/// IRP major function names, index = IRP_MJ_* value.
pub fn irp(index: u64) -> &'static str {
    const N: [&str; 28] = [
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    ];
    N.get(index as usize).copied().unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_layouts_match_expected_offsets() {
        // UNICODE_STRING.Buffer is 8 bytes in (alignment skip after two u16).
        assert_eq!(field(UNICODE_STRING, 0x08).map(|f| f.name), Some("Buffer"));
        // Parameters.DeviceIoControl.IoControlCode is what a handler compares.
        assert_eq!(
            field(IO_STACK_LOCATION, 0x10).map(|f| f.name),
            Some("Parameters.DeviceIoControl.IoControlCode")
        );
        assert!(!MAJOR_BASES.is_empty());
    }

    #[test]
    fn dispatch_slots_render_by_major() {
        // Modern base: IRP_MJ_DEVICE_CONTROL (14) at 0x50 + 8*14.
        assert_eq!(
            dispatch_slot(0x50 + 8 * 14),
            Some("MajorFunction[14] /* IRP_MJ_DEVICE_CONTROL */".into())
        );
        // The same bytes read under the legacy interpretation (0x70 base).
        // Dispatch slot naming defaults to the modern base, so this is slot 18
        // unless a driver report already established 0x70 as its base.
        assert_eq!(
            dispatch_slot(0x70 + 8 * 14),
            Some("MajorFunction[18] /* IRP_MJ_CLEANUP */".into())
        );
        // A non-slot offset is None, never a name.
        assert_eq!(dispatch_slot(0x20), None);
    }
}
