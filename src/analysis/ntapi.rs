//! Native / kernel-mode API catalogue.
//!
//! The user-mode sink catalogue (`sinks`) answers "where would an overflow
//! live"; this one answers the other half of a driver audit: "what kernel
//! capability does this driver reach for, and is that capability a BYOVD
//! primitive". Entries are WDM/`ntoskrnl`/`hal`/`ndis` APIs grouped by the
//! primitive they expose rather than by the module they live in, and they are
//! merged into the same call-site machinery so `knife sinks` / `knife drv`
//! both see them with xrefs attached.

use super::sinks::SinkDef;

macro_rules! nt {
    ($api:literal, $class:literal, $note:literal, $sev:literal) => {
        SinkDef {
            api: $api,
            class: $class,
            note: $note,
            severity: $sev,
        }
    };
}

/// Kernel-mode catalog. `severity` follows the `sinks` convention: 3 = a
/// primitive that no sane signed driver needs unless it is doing something
/// unusual (arbitrary physical memory access), 2 = a real capability that is
/// the standard building block of exploit primitives (mapping a section into
/// another process), 1 = routine plumbing worth seeing on a target.
pub static KERNEL_CATALOG: &[SinkDef] = &[
    // ── physical memory access: the core BYOVD primitive ──
    nt!("MmMapIoSpace", "physical-mem", "maps a physical range into the driver; if the app can pick physical addresses, it can touch anything", 3),
    nt!("MmMapIoSpaceEx", "physical-mem", "MmMapIoSpace with explicit cache type; same primitive", 3),
    nt!("MmMapLockedPages", "physical-mem", "maps locked MDL pages (physical) into the driver", 3),
    nt!("MmMapLockedPagesSpecifyCache", "physical-mem", "MDL-backed physical mapping with cache type", 3),
    nt!("MmMapPhysicalMemory", "physical-mem", "physical-range mapping; RAW-driver staple", 3),
    nt!("MmMapPhysicalMemoryEx", "physical-mem", "physical-range mapping, securable", 3),
    nt!("MmUnmapIoSpace", "physical-mem", "unmaps a physical mapping", 1),
    nt!("MmUnmapLockedPages", "physical-mem", "unmaps an MDL mapping", 1),
    // ── arbitrary memory read/write primitives ──
    nt!("MmCopyVirtualMemory", "kernel-rw", "read/write another process's memory by address; arbitrary R/W primitive", 3),
    nt!("MmProbeAndLockPages", "kernel-rw", "locks user pages the driver has been handed", 2),
    nt!("MmBuildMdlForNonPagedPool", "kernel-rw", "make an MDL over driver memory", 2),
    nt!("MmGetSystemRoutineAddress", "kernel-rw", "resolves an arbitrary kernel routine by name at runtime", 3),
    nt!("MmAllocateContiguousMemory", "kernel-rw", "allocate physically contiguous memory", 2),
    nt!("MmAllocateContiguousMemorySpecifyCache", "kernel-rw", "allocate physically contiguous memory", 2),
    nt!("MmAllocatePagesForMdl", "kernel-rw", "allocate physical pages into an MDL", 2),
    nt!("MmMapMdl", "kernel-rw", "map an MDL into the system space", 2),
    nt!("MmFreeContiguousMemory", "kernel-rw", "free contiguous memory", 1),
    nt!("MmProtectMdlSystemAddress", "kernel-rw", "change protections on an MDL mapping", 2),
    // ── port / bus I/O ──
    nt!("WRITE_PORT_ULONG", "io-port", "raw port write; trivial to turn into arbitrary kernel I/O with ioctls", 3),
    nt!("WRITE_PORT_USHORT", "io-port", "raw port write", 3),
    nt!("WRITE_PORT_UCHAR", "io-port", "raw port write", 3),
    nt!("READ_PORT_ULONG", "io-port", "raw port read", 2),
    nt!("READ_PORT_USHORT", "io-port", "raw port read", 2),
    nt!("READ_PORT_UCHAR", "io-port", "raw port read", 2),
    nt!("WRITE_PORT_BUFFER_ULONG", "io-port", "block port write", 3),
    nt!("HalTranslateBusAddress", "io-port", "translate a bus address; often the ramp onto physical-memory tricks", 2),
    nt!("HalGetBusDataByOffset", "io-port", "direct config-space (PCI) access", 2),
    nt!("HalSetBusDataByOffset", "io-port", "direct config-space (PCI) write", 3),
    // ── driver loading ──
    nt!("NtLoadDriver", "loader", "loads a driver by registry key; the canonical 'install a rootkit' primitive", 3),
    nt!("ZwLoadDriver", "loader", "Zw form of NtLoadDriver", 3),
    nt!("NtUnloadDriver", "loader", "unloads a driver", 2),
    nt!("IoCreateDriver", "loader", "instantiate a driver object from a function pointer", 3),
    nt!("MmLoadSystemImage", "loader", "map another kernel image into memory", 2),
    // ── callbacks / notifiers ──
    nt!("ObRegisterCallbacks", "callback", "observe/intercept handle open/duplicate; used for callback-based EDR bypass or protection", 3),
    nt!("ObUnRegisterCallbacks", "callback", "remove a registered callback", 1),
    nt!("PsSetCreateProcessNotifyRoutine", "callback", "process creation/exit notification", 2),
    nt!("PsSetCreateProcessNotifyRoutineEx", "callback", "process notification with context", 2),
    nt!("PsSetCreateThreadNotifyRoutine", "callback", "thread creation notification", 2),
    nt!("PsSetLoadImageNotifyRoutine", "callback", "module load notification", 2),
    nt!("CmRegisterCallback", "callback", "registry callbacks; persistent tamper-detection/bypass surface", 3),
    nt!("CmRegisterCallbackEx", "callback", "registry callbacks with context", 3),
    nt!("CmUnRegisterCallback", "callback", "remove a registry callback", 1),
    nt!("IoRegisterBootDriverReinitialization", "callback", "boot-time reinit hook", 1),
    nt!("IoRegisterDriverReinitialization", "callback", "reinit hook", 1),
    // ── device / object surface (the ioctl attack surface) ──
    nt!("IoCreateDevice", "device", "creates a device object; the driver's ioctl entry point", 2),
    nt!("IoCreateDeviceSecure", "device", "creates a device with a security descriptor", 2),
    nt!("IoDeleteDevice", "device", "removes a device object", 1),
    nt!("IoCreateSymbolicLink", "device", "exposes the device to user mode via \\DosDevices\\ or \\??\\", 2),
    nt!("IoDeleteSymbolicLink", "device", "remove a symbolic link", 1),
    nt!("IoRegisterDeviceInterface", "device", "register a device interface (enumerable surface)", 2),
    nt!("IoSetDeviceInterfaceState", "device", "enable/disable a registered interface", 2),
    nt!("IoGetDeviceObjectPointer", "device", "opens another device; cross-device attack surface", 2),
    nt!("IoGetDeviceProperty", "device", "query device properties", 1),
    nt!("IoCreateFile", "device", "open a device/file from kernel", 1),
    nt!("IoCallDriver", "device", "forward an IRP", 2),
    nt!("IofCallDriver", "device", "forward an IRP (fast-call form)", 2),
    nt!("IoBuildDeviceIoControlRequest", "device", "build an ioctl IRP from kernel", 2),
    nt!("IoGetCurrentIrpStackLocation", "device", "recover IRP parameters (ioctl codes)", 1),
    nt!("IoAllocateIrp", "device", "allocate an IRP", 1),
    nt!("IoFreeIrp", "device", "free an IRP", 1),
    // ── process / virtual-memory ──
    nt!("ZwOpenProcess", "process", "open another process; the handshaking step of a R/W primitive", 3),
    nt!("ZwOpenThread", "process", "open a thread in another process", 3),
    nt!("ZwReadVirtualMemory", "process", "read another process's memory", 3),
    nt!("ZwWriteVirtualMemory", "process", "write another process's memory; arbitrary-kernel-write contender", 3),
    nt!("ZwProtectVirtualMemory", "process", "change protection on another process's memory", 3),
    nt!("ZwMapViewOfSection", "process", "map a section into another process", 2),
    nt!("ZwAllocateVirtualMemory", "process", "allocate memory in another process", 2),
    nt!("ZwQueryVirtualMemory", "process", "probe another process's memory", 1),
    nt!("KeStackAttachProcess", "process", "run in another process's address space", 3),
    nt!("KeUnstackDetachProcess", "process", "leave an attached process", 1),
    nt!("PsLookupProcessByProcessId", "process", "resolve an EPROCESS from a PID", 1),
    nt!("PsGetProcessImageFileName", "process", "get a process image name", 1),
    nt!("ZwTerminateProcess", "process", "kill a process", 3),
    // ── pool ──
    nt!("ExAllocatePool", "pool", "legacy pool allocation (deprecated; no `Pool2` tag semantics)", 3),
    nt!("ExAllocatePoolWithTag", "pool", "tagged pool allocation", 2),
    nt!("ExAllocatePool2", "pool", "tagged pool allocation", 2),
    nt!("ExAllocatePoolWithQuotaTag", "pool", "tagged pool with quota", 2),
    nt!("ExFreePool", "pool", "free pool memory", 1),
    nt!("ExFreePoolWithTag", "pool", "free tagged pool", 1),
    nt!("ExFreePool2", "pool", "free tagged pool", 1),
    // ── registry ──
    nt!("ZwOpenKey", "registry", "open a registry key", 1),
    nt!("ZwCreateKey", "registry", "create a registry key", 1),
    nt!("ZwSetValueKey", "registry", "write a registry value; persistence", 2),
    nt!("ZwQueryValueKey", "registry", "read a registry value", 1),
    nt!("ZwDeleteKey", "registry", "delete a registry key", 2),
    nt!("ZwClose", "registry", "close a handle", 1),
    // ── security / privileges ──
    nt!("SeAssignSecurity", "security", "build a security descriptor", 2),
    nt!("SeSinglePrivilegeCheck", "security", "check a single privilege", 1),
    nt!("SePrivilegeCheck", "security", "check privileges", 1),
    nt!("RtlAdjustPrivilege", "security", "raise/alter a privilege (e.g. SeDebugPrivilege)", 3),
    nt!("RtlGetVersion", "security", "query OS version", 1),
    // ── file / system info ──
    nt!("ZwCreateFile", "file", "kernel file create", 1),
    nt!("ZwReadFile", "file", "kernel file read", 1),
    nt!("ZwWriteFile", "file", "kernel file write", 1),
    nt!("ZwQueryInformationFile", "file", "query file info", 1),
    nt!("ZwQuerySystemInformation", "file", "enumerate system objects/processes", 2),
    // ── synchronization (rule these out while auditing) ──
    nt!("KeInitializeMutex", "sync", "mutex init", 1),
    nt!("KeInitializeSemaphore", "sync", "semaphore init", 1),
    nt!("KeInitializeSpinLock", "sync", "spinlock init", 1),
    nt!("KeInitializeEvent", "sync", "event init", 1),
    nt!("KeWaitForSingleObject", "sync", "wait on a dispatcher object", 1),
    nt!("KeAcquireSpinLock", "sync", "spinlock acquire", 1),
    nt!("IoCreateNotificationEvent", "sync", "named notification event", 1),
    nt!("KeDelayExecutionThread", "sync", "delay (timers/sleep)", 1),
    // ── NDIS (network drivers) ──
    nt!("NdisRegisterProtocol", "netio", "register an NDIS protocol driver", 2),
    nt!("NdisDeregisterProtocol", "netio", "unregister an NDIS protocol", 1),
    nt!("NdisOpenAdapter", "netio", "open an adapter; network filter hooking surface", 2),
    nt!("NdisCloseAdapter", "netio", "close an adapter", 1),
    nt!("NdisSendNetBufferLists", "netio", "send network data", 2),
    nt!("NdisAllocateMemoryWithTagPriority", "netio", "alloc with priority", 2),
    nt!("NdisAllocateNetBufferAndNetBufferList", "netio", "alloc network buffer chain", 1),
    nt!("NdisAllocateNetBuffer", "netio", "alloc a net buffer", 1),
    nt!("NdisAllocateNetBufferList", "netio", "alloc a net buffer list", 1),
    nt!("NdisFreeNetBufferList", "netio", "free a net buffer list", 1),
    nt!("NdisRegisterProtocolDriver", "netio", "register a protocol driver", 1),
    nt!("NdisDeregisterProtocolDriver", "netio", "deregister a protocol driver", 1),
    nt!("NdisMRegisterMiniportDriver", "netio", "register a miniport driver", 1),
    nt!("NdisMDeregisterMiniportDriver", "netio", "deregister a miniport driver", 1),
    // ── work items / WMI ──
    nt!("ExQueueWorkItem", "other", "queue a work item (deferred execution)", 2),
    nt!("IoWMIRegistrationControl", "other", "WMI registration control", 1),
];

/// System-DLL import modules. The driver pass uses this to split the kernel
/// surface (ntoskrnl & friends) from app-layer or third-party DLLs.
#[allow(dead_code)] // consumed by the `knife drv` pass
pub fn is_system_module(module: &str) -> bool {
    matches!(
        module.to_ascii_lowercase().as_str(),
        "ntoskrnl"
            | "ntkrnlmp"
            | "ntkrnlpa"
            | "ntkrnlpaex"
            | "hal"
            | "ndis"
            | "wdm"
            | "wdfload"
            | "wdffdo"
            | "wdflibrarian"
            | "ci"
            | "cng"
            | "ksecdd"
            | "fltmgr"
            | "tcpip"
            | "classpnp"
            | "mountmgr"
            | "nsiproxy"
            | "netio"
            | "video"
            | "watchdog"
    )
}
