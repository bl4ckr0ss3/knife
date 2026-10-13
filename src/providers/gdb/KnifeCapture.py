"""Knife-owned bounded GDB capture. This DOES execute the authorized target."""
import json
import re
import gdb

report = {"schema": 1, "provider": "gdb", "target_execution": True,
          "stop": None, "steps_completed": 0, "error": None}
try:
    steps = int(gdb.parse_and_eval("$knife_steps"))
    if not 0 <= steps <= 128:
        raise ValueError("step count out of range")
    gdb.execute("starti", to_string=True)
    # The kernel's auxv names this executable's relocated entry, not ld.so's PC.
    auxv = gdb.execute("info auxv", to_string=True)
    entry = re.search(r"^\s*9\s+AT_ENTRY\s+.*?\s+(0x[0-9a-fA-F]+)\s*$", auxv, re.M)
    if entry is None:
        raise RuntimeError("runtime executable entry unavailable in auxiliary vector")
    runtime_entry = int(entry.group(1), 16)
    report["runtime_entry"] = hex(runtime_entry)
    if int(gdb.parse_and_eval("$pc")) != runtime_entry:
        gdb.execute("tbreak *" + hex(runtime_entry), to_string=True)
        gdb.execute("continue", to_string=True)
    if int(gdb.parse_and_eval("$pc")) != runtime_entry:
        raise RuntimeError("target stopped before reaching its executable entry")
    for _ in range(steps):
        gdb.execute("stepi", to_string=True)
        report["steps_completed"] += 1
    inferior = gdb.selected_inferior()
    pc = int(gdb.parse_and_eval("$pc"))
    sp = int(gdb.parse_and_eval("$sp"))
    stop = {"runtime_pc": hex(pc), "runtime_sp": hex(sp), "pid": inferior.pid,
            "frames": [], "memory_hex": None}
    frame = gdb.newest_frame()
    while frame is not None and len(stop["frames"]) < 16:
        stop["frames"].append({"runtime_pc": hex(frame.pc()), "name": frame.name()})
        frame = frame.older()
    try:
        stop["memory_hex"] = bytes(inferior.read_memory(pc, 64)).hex()
    except gdb.MemoryError as error:
        stop["memory_error"] = str(error)[:2048]
    report["stop"] = stop
except Exception as error:
    report["error"] = str(error)[:2048]
finally:
    if gdb.selected_inferior().pid:
        try:
            gdb.execute("kill", to_string=True)
        except gdb.error as error:
            report["cleanup_error"] = str(error)[:2048]
    print("KNIFE_GDB_JSON:" + json.dumps(report, ensure_ascii=True))
