import os
import subprocess
import time
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
import asyncio

app = Server("Talos_Sentry_Forensics")

# --- DECEPTION CONFIG ---
CANARY_FILES = {
    "aws": os.path.expanduser("~/.aws/credentials_canary"),
    "kube": os.path.expanduser("~/.kube/config_canary"),
    "env": "./.env.production.bak"
}

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="deploy_canaries",
            description="Deploys 'honeytoken' files that the Mini Shai-Hulud worm targets.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="audit_canary_access",
            description="Checks if any canary files have been read (accessed) since deployment.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="find_evil_scan",
            description="Forensic scan for Shai-Hulud signatures and recent 2026 IOCs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "The path to scan for EVIL"}
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="analyze_usb_triage",
            description="Analyze a SANS USB Incident Response report folder, mapping network sockets to processes and resolving false positives.",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_dir": {"type": "string", "description": "Path to the Ares_Forensics_Report directory"}
                },
                "required": ["report_dir"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "deploy_canaries":
        for key, path in CANARY_FILES.items():
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w") as f:
                f.write(f"# Fake {key.upper()} Credentials for Project Talos\n")
                f.write(f"{key}_access_key_id=AKIA_DECEPTION_TRAP_{int(time.time())}\n")
        return [types.TextContent(type="text", text=f"Canaries deployed at: {list(CANARY_FILES.values())}")]

    elif name == "audit_canary_access":
        triggered = []
        for key, path in CANARY_FILES.items():
            if os.path.exists(path):
                atime = os.path.getatime(path)
                mtime = os.path.getmtime(path)
                # If the file was read (atime) after it was created/modified
                if atime > mtime + 1: 
                    triggered.append(f"ALERT: {key.upper()} canary accessed at {time.ctime(atime)}!")
        
        result = "\n".join(triggered) if triggered else "All traps untouched."
        return [types.TextContent(type="text", text=result)]

    elif name == "find_evil_scan":
        path = arguments.get("path", ".")
        iocs = ["setup.mjs", "execution.js", "bun_environment.js"]
        findings = [f for f in iocs if os.path.exists(os.path.join(path, f))]
        
        # Check for the 2026 'WormyBoi' propagation string manually
        for root, _, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        if 'EveryBoiWeBuildIsAWormyBoi' in f.read():
                            findings.append(f"PROPAGATION STRING DETECTED in {filepath}")
                except Exception:
                    pass
        
        result = "\n".join(findings) if findings else "Workspace clean."
        return [types.TextContent(type="text", text=result)]

    elif name == "analyze_usb_triage":
        report_dir = arguments.get("report_dir")
        if not report_dir or not os.path.exists(report_dir):
            return [types.TextContent(type="text", text=f"Error: Directory {report_dir} not found.")]

        import csv
        processes_file = os.path.join(report_dir, "processes.csv")
        network_file = os.path.join(report_dir, "network_connections.txt")
        
        process_map = {}
        # Parse processes
        if os.path.exists(processes_file):
            try:
                # UTF-16LE or UTF-8 check
                with open(processes_file, 'r', encoding='utf-16' if os.path.getsize(processes_file) > 100 and b'\xff\xfe' in open(processes_file, 'rb').read(2) else 'utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        pid = row.get("ProcessId")
                        if pid:
                            process_map[pid] = {
                                "name": row.get("Name", "Unknown"),
                                "cmd": row.get("CommandLine", ""),
                                "path": row.get("ExecutablePath", ""),
                                "parent": row.get("ParentProcessId", "")
                            }
            except Exception as e:
                pass

        # Parse connections
        connections = []
        anomalies = []
        false_positives = []
        
        # Known safe false positive signatures (anti-virus, VPN, system)
        safe_keywords = ["surfshark", "tailscale", "proton", "mullvad", "windscribe", "avast", "malwarebytes", "mcafee"]

        if os.path.exists(network_file):
            try:
                with open(network_file, 'r', encoding='utf-16' if b'\xff\xfe' in open(network_file, 'rb').read(2) else 'utf-8-sig') as f:
                    for line in f:
                        if "CLOSE_WAIT" in line or "ESTABLISHED" in line:
                            parts = line.strip().split()
                            if len(parts) >= 5:
                                proto = parts[0]
                                local = parts[1]
                                foreign = parts[2]
                                state = parts[3]
                                pid = parts[4]
                                
                                # Resolve process metadata
                                proc_info = process_map.get(pid, {"name": "Unknown", "path": "", "cmd": ""})
                                conn_data = {
                                    "proto": proto,
                                    "local": local,
                                    "foreign": foreign,
                                    "state": state,
                                    "pid": pid,
                                    "proc_name": proc_info["name"],
                                    "proc_path": proc_info["path"]
                                }
                                connections.append(conn_data)
                                
                                # Verify if connection is a false positive
                                is_safe = False
                                for kw in safe_keywords:
                                    if kw in proc_info["name"].lower() or kw in proc_info["path"].lower() or kw in proc_info["cmd"].lower():
                                        is_safe = True
                                        break
                                
                                if is_safe:
                                    false_positives.append(conn_data)
                                else:
                                    # Standard system checks
                                    if proc_info["name"] != "Unknown":
                                        # Outbound from user space temp/appdata
                                        if "temp" in proc_info["path"].lower() or "appdata" in proc_info["path"].lower():
                                            anomalies.append(conn_data)

            except Exception as e:
                return [types.TextContent(type="text", text=f"Error parsing connections: {str(e)}")]

        summary = {
            "status": "success",
            "total_connections_monitored": len(connections),
            "anomalies_detected": len(anomalies),
            "false_positives_resolved": len(false_positives),
            "anomalous_processes": anomalies,
            "resolved_processes": false_positives
        }
        return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

    raise ValueError(f"Unknown tool: {name}")

async def main():
    print("Talos Forensics MCP starting up...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
