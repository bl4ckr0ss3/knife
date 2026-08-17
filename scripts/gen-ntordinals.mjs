#!/usr/bin/env node
// Generates src/analysis/nt_ordinals.rs (a Rust const table of
// {module, ordinal, api-name}) from the PE export directories of real system
// DLLs on this machine. Only entries whose name appears in the knife kernel
// catalog are kept, so the table is small and every row is meaningful to the
// flagship (`knife sinks` / `knife drv`).
//
// Usage: node scripts/gen-ntordinals.mjs [path-to-dll ...]
// Defaults to ntoskrnl.exe and ndis.sys from the system32/drivers paths.

import fs from 'node:fs';

const NT_ORDINALS_OUT = 'src/analysis/nt_ordinals.rs';

// Names covered by the kernel catalog (src/analysis/ntapi.rs). Only these get
// ordinal-resolution rows; add new NT API entries here when extending the
// catalog so the generator keeps picking up their ordinals.
const FILTER = new Set([
  // memory / physical
  'MmMapIoSpace', 'MmMapIoSpaceEx', 'MmMapLockedPages', 'MmMapLockedPagesSpecifyCache',
  'MmMapPhysicalMemory', 'MmMapPhysicalMemoryEx', 'MmUnmapIoSpace', 'MmUnmapLockedPages',
  'MmCopyVirtualMemory', 'MmProbeAndLockPages', 'MmAllocateContiguousMemory',
  'MmAllocateContiguousMemorySpecifyCache', 'MmAllocatePagesForMdl', 'MmMapMdl',
  'MmFreeContiguousMemory', 'MmGetSystemRoutineAddress',
  // process / access
  'ZwOpenProcess', 'ZwOpenThread', 'ZwReadVirtualMemory', 'ZwWriteVirtualMemory',
  'ZwProtectVirtualMemory', 'ZwMapViewOfSection', 'ZwQueryVirtualMemory',
  'ZwAllocateVirtualMemory', 'KeStackAttachProcess', 'KeUnstackDetachProcess',
  'PsLookupProcessByProcessId', 'PsGetProcessImageFileName', 'ZwTerminateProcess',
  // loader
  'NtLoadDriver', 'ZwLoadDriver', 'NtUnloadDriver', 'IoCreateDriver', 'MmLoadSystemImage',
  // callbacks / notifiers
  'ObRegisterCallbacks', 'ObUnRegisterCallbacks', 'PsSetCreateProcessNotifyRoutine',
  'PsSetCreateProcessNotifyRoutineEx', 'PsSetCreateThreadNotifyRoutine',
  'PsSetLoadImageNotifyRoutine', 'CmRegisterCallback', 'CmRegisterCallbackEx',
  'IoRegisterBootDriverReinitialization', 'IoRegisterDriverReinitialization',
  // device / object
  'IoCreateDevice', 'IoCreateDeviceSecure', 'IoDeleteDevice', 'IoCreateSymbolicLink',
  'IoDeleteSymbolicLink', 'IoRegisterDeviceInterface', 'IoGetDeviceObjectPointer',
  'IoGetDeviceProperty', 'IoCreateFile', 'IoCallDriver', 'IoBuildDeviceIoControlRequest',
  'IoGetCurrentIrpStackLocation', 'IoAllocateIrp', 'IoFreeIrp', 'IofCallDriver',
  'IoCheckShareAccess', 'IoGetAttachedDeviceReference', 'IoGetDeviceObjectPointer',
  // sync / mutex / timers (a driver pollutes here)
  'KeInitializeMutex', 'KeInitializeSemaphore', 'KeInitializeSpinLock', 'KeInitializeEvent',
  'KeWaitForSingleObject', 'KeDelayExecutionThread', 'KeAcquireSpinLock', 'IoCreateNotificationEvent',
  // pool
  'ExAllocatePool', 'ExAllocatePoolWithTag', 'ExAllocatePool2', 'ExAllocatePoolWithQuotaTag',
  'ExFreePool', 'ExFreePoolWithTag', 'ExFreePool2',
  // registry
  'ZwOpenKey', 'ZwCreateKey', 'ZwSetValueKey', 'ZwQueryValueKey', 'ZwDeleteKey', 'ZwClose',
  // security / privileges
  'SeSinglePrivilegeCheck', 'SePrivilegeCheck', 'SeAssignSecurity', 'RtlAdjustPrivilege',
  'RtlGetVersion', 'RtlInitUnicodeString', 'RtlPrefixUnicodeString', 'RtlEqualUnicodeString',
  'RtlCopyUnicodeString', 'RtlAnsiStringToUnicodeString', 'RtlFreeUnicodeString',
  // file
  'ZwCreateFile', 'ZwReadFile', 'ZwWriteFile', 'ZwQueryInformationFile', 'ZwQuerySystemInformation',
  // wmi / power / driver-specific
  'IoWMIRegistrationControl', 'IoSetDeviceInterfaceState', 'ExQueueWorkItem',
  // netio (ndis)
  'NdisRegisterProtocol', 'NdisDeregisterProtocol', 'NdisOpenAdapter', 'NdisCloseAdapter',
  'NdisSendNetBufferLists', 'NdisAllocateMemoryWithTagPriority', 'NdisAllocateNetBufferAndNetBufferList',
  'NdisAllocateNetBuffer', 'NdisAllocateNetBufferList', 'NdisFreeNetBufferList', 'NdisRegisterProtocolDriver',
  'NdisDeregisterProtocolDriver', 'NdisMRegisterMiniportDriver', 'NdisMDeregisterMiniportDriver',
]);

function sectionRvaToOffset(buf, rva) {
  const pe = readDosHeader(buf);
  if (pe + 4 + 20 > buf.length) return -1;
  const nsec = buf.readUInt16LE(pe + 6);
  const optSize = buf.readUInt16LE(pe + 20);
  const firstSection = pe + 24 + optSize;
  for (let i = 0; i < nsec; i++) {
    const s = firstSection + i * 40;
    const vaddr = buf.readUInt32LE(s + 12);
    const vsize = buf.readUInt32LE(s + 8);
    const rawOff = buf.readUInt32LE(s + 20);
    if (rva >= vaddr && rva < vaddr + vsize) return rawOff + (rva - vaddr);
  }
  return -1;
}

function readDosHeader(buf) { return buf.readUInt32LE(0x3c); }

function parseExports(buf, dllPath) {
  function cstr(off) {
    if (off < 0 || off >= buf.length) return '';
    const end = buf.indexOf(0, off);
    if (end < 0) return '';
    return buf.toString('latin1', off, end);
  }
  const pe = readDosHeader(buf);
  const opt = pe + 24;
  const magic = buf.readUInt16LE(opt);
  const dirsOff = magic === 0x20b ? opt + 112 : opt + 96;
  const expRva = buf.readUInt32LE(dirsOff + 0); // export directory is index 0
  const expSize = buf.readUInt32LE(dirsOff + 4);
  const exp = sectionRvaToOffset(buf, expRva);
  if (exp < 0 || exp + 40 > buf.length) return [];
  const base = buf.readUInt32LE(exp + 16);
  const nFuncs = buf.readUInt32LE(exp + 20);
  const nNames = buf.readUInt32LE(exp + 24);
  const offFuncs = sectionRvaToOffset(buf, buf.readUInt32LE(exp + 28));
  const offNames = sectionRvaToOffset(buf, buf.readUInt32LE(exp + 32));
  const offOrds = sectionRvaToOffset(buf, buf.readUInt32LE(exp + 36));
  const names = new Map();
  for (let i = 0; i < nNames; i++) {
    const nameRva = buf.readUInt32LE(offNames + i * 4);
    const nameOff = sectionRvaToOffset(buf, nameRva);
    if (nameOff < 0) continue;
    const name = cstr(nameOff);
    if (!name) continue;
    const ord = buf.readUInt16LE(offOrds + i * 2);
    names.set(name, base + ord);
  }
  return names;
}

const moduleBase = (p) => pathBase(p);
function pathBase(p) {
  const b = p.split(/[\\/]/).pop();
  return b.replace(/\.(sys|dll|exe)$/i, '').toLowerCase();
}

const candidates = process.argv.slice(2);
const search = {
  'ntoskrnl': ['C:\\Windows\\System32\\ntoskrnl.exe'],
  'ndis': ['C:\\Windows\\System32\\drivers\\ndis.sys', 'C:\\Windows\\System32\\ndis.sys'],
};

const rows = [];
const seen = new Set();
const modules = candidates.length || 1;
for (const [mod, paths] of Object.entries(search)) {
  if (candidates.length && !candidates.includes(mod)) continue;
  const found = paths.find(p => fs.existsSync(p));
  if (!found) { console.error(`[warn] no ${mod} at ${paths.join(' / ')}`); continue; }
  const buf = fs.readFileSync(found);
  const names = parseExports(buf, found);
  for (const [name, ord] of names) {
    if (FILTER.has(name)) {
      const key = `${mod}:${ord}`;
      if (!seen.has(key)) { seen.add(key); rows.push({ mod, ord, name }); }
    }
  }
  console.error(`[info] ${mod}: ${names.size} exports, ${rows.length} kept after filter`);
}

rows.sort((a, b) => a.mod.localeCompare(b.mod) || a.ord - b.ord);

const lines = rows.map(r => `    ("${r.mod}", ${r.ord}, "${r.name}"),`).join('\n');
const out = `//! Generated by scripts/gen-ntordinals.mjs -- DO NOT EDIT BY HAND.
//!
//! Ordinal -> API mappings for kernel modules whose imports are commonly found
//! as bare ordinals (a stripping pattern in drivers). Sourced from the export
//! directories of the host's own ntoskrnl.exe / ndis.sys during development so
//! every row is a real export, filtered to names the kernel catalog flags.
//! Regenerate with: node scripts/gen-ntordinals.mjs

/// Tuple of (module-base-name, ordinal, api-name).
pub const NT_ORDINALS: &[(&str, u16, &str)] = &[
${lines}
];

/// Resolve an ordinal import 'module!ORDINAL n' to a catalog-known API name.
/// Unknown ordinals fall through to None and keep the synthetic 'ORDINAL N'.
pub fn resolve_ordinal(module: &str, ordinal: u16) -> Option<&'static str> {
    let module = module.to_ascii_lowercase();
    NT_ORDINALS
        .iter()
        .find(|(m, o, _)| *m == module && *o == ordinal)
        .map(|(_, _, n)| *n)
}
`;
fs.writeFileSync(NT_ORDINALS_OUT, out);
console.log(`wrote ${NT_ORDINALS_OUT}: ${rows.length} rows`);