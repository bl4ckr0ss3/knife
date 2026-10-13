#!/usr/bin/env python3
"""Live static-only MCP validation; requires configured Ghidra and Java."""
import json
import select
import subprocess
import sys
import time


def main():
    binary, target = sys.argv[1:3]
    server = subprocess.Popen(
        [binary, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    sequence = 0

    def request(method, params):
        nonlocal sequence
        sequence += 1
        server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": sequence,
                                     "method": method, "params": params}) + "\n")
        server.stdin.flush()
        if not select.select([server.stdout], [], [], 330)[0]:
            raise TimeoutError("MCP response exceeded validation deadline")
        line = server.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed output")
        response = json.loads(line)
        assert response["id"] == sequence, response
        if "error" in response:
            raise RuntimeError(response["error"])
        result = response["result"]
        if result.get("isError"):
            raise RuntimeError(result)
        return result

    def tool(name, args):
        return request("tools/call", {"name": name, "arguments": args})

    try:
        request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "knife-ghidra-validation", "version": "1"}})
        tools = request("tools/list", {})["tools"]
        assert {"ghidra_functions", "ghidra_decompile"} <= {t["name"] for t in tools}
        tool("open", {"file": target})
        tool("session_status", {})
        started = time.monotonic()
        first = tool("ghidra_functions", {"limit": 2, "timeout_seconds": 120})
        first_seconds = time.monotonic() - started
        content = first["structuredContent"]
        retained = tool("get_retained_result", {
            "result_id": first["_meta"]["knife/resultId"]
        })["structuredContent"]
        assert retained["payload"] == content
        data = content["data"]
        assert data["workspace_sha256"] == data["sample_sha256"]
        assert data["target_execution"] is False
        assert content["evidence"]
        assert all(loc.get("runtime_address") is None
                   for e in content["evidence"] for loc in e["locations"])
        cursor = data["next_cursor"]
        assert cursor, "target must contain more than two functions"
        started = time.monotonic()
        second = tool("ghidra_functions", {"limit": 2, "timeout_seconds": 120, "cursor": cursor})
        second_seconds = time.monotonic() - started
        second_data = second["structuredContent"]["data"]
        assert second_data["result_sha256"] == data["result_sha256"]
        assert second_data["page"]["offset"] == 2
        entry = data["functions"][0]
        assert entry["file_offset"] is not None
        assert entry["knife_static_address"] is not None
        navigation = tool("inspect_address_context", {
            "address": entry["knife_static_address"]
        })["structuredContent"]
        assert navigation["evidence"], "mapped entry must be navigable"
        comparison = tool("compare_engine_findings", {
            "address": entry["knife_static_address"],
            "include_ghidra": True, "timeout_seconds": 120
        })["structuredContent"]
        ghidra_fields = [row for row in comparison["data"]["comparisons"]
                         if row.get("provider") == "ghidra"]
        assert len(ghidra_fields) == 2
        # Ghidra may recover an entry that Knife did not; that stays unknown.
        native = comparison["data"]["knife"]
        assert ghidra_fields[0]["status"] == ("agreement" if native else "unknown"), comparison
        assert any(e["producer"] == "ghidra_functions" for e in comparison["evidence"])
        decompiled = tool("ghidra_decompile", {
            "provider_static_address": entry["address"], "timeout_seconds": 120
        })["structuredContent"]
        assert decompiled["data"]["decompile_completed"] is True
        assert decompiled["data"]["pseudocode"]
        assert decompiled["data"]["function"]["file_offset"] == entry["file_offset"]
        print(json.dumps({"target": target, "workspace_sha256": data["workspace_sha256"],
                          "total_functions": data["total"], "inventory_partial": content["partial"],
                          "first_page_seconds": round(first_seconds, 3),
                          "cached_page_seconds": round(second_seconds, 3),
                          "entry": entry, "decompile_partial": decompiled["partial"],
                          "ghidra_comparison": ghidra_fields,
                          "knife_comparison": native,
                          "pseudocode": decompiled["data"]["pseudocode"][:1000],
                          "evidence_locations": decompiled["evidence"][0]["locations"]}, indent=2))
    finally:
        server.stdin.close()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
