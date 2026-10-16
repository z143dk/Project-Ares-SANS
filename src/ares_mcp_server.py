import asyncio
import json
import os
from datetime import datetime
from mcp.server import Server
import mcp.types as types
from mcp.server.stdio import stdio_server

# Initialize the Project Ares MCP Server
app = Server("Project-Ares-DFIR")

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    """
    List the available DFIR tools for the SANS hackathon.
    Our agent will use these tools to 'Find Evil'.
    """
    return [
        types.Tool(
            name="analyze_pcap",
            description="Analyze a PCAP (Packet Capture) file for malicious network traffic.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap file on the SIFT workstation"
                    }
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="extract_strings",
            description="Extract printable strings from a suspicious executable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the suspicious binary"
                    }
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="workspace_search",
            description="Search the local workspace for relevant files and content using a keyword or pattern.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The text or keyword to search for in the workspace"
                    },
                    "directory": {
                        "type": "string",
                        "description": "Optional directory path to restrict the search"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="write_research_log",
            description="Write a finding or RAG critique to the RESEARCH_LOG.md memory file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entry": {
                        "type": "string",
                        "description": "The markdown entry to append to the log"
                    }
                },
                "required": ["entry"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """
    Execute the requested DFIR tool.
    In the actual hackathon, we will wire these up to real SIFT workstation commands (e.g. tshark, strings).
    """
    if name == "analyze_pcap":
        pcap_file = arguments.get("file_path")
        # TODO: Implement actual pcap analysis using tshark or scapy
        result = f"[SIMULATION] Analyzed {pcap_file}. No immediate C2 beacons detected."
        return [types.TextContent(type="text", text=result)]
        
    elif name == "extract_strings":
        binary_file = arguments.get("file_path")
        # TODO: Implement actual string extraction
        result = f"[SIMULATION] Extracted strings from {binary_file}. Found suspicious URL: http://evil.local/payload.exe"
        return [types.TextContent(type="text", text=result)]
        
    elif name == "workspace_search":
        query = arguments.get("query")
        directory = arguments.get("directory") or "."
        results = []
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    if '.git' in root or 'node_modules' in root or '__pycache__' in root:
                        continue
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if query.lower() in content.lower():
                                results.append(f"[Source: {file_path}] Match found in file.")
                    except Exception:
                        pass
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error searching workspace: {str(e)}")]
            
        if results:
            result_text = f"Found matches in {len(results)} files:\n" + "\n".join(results[:5])
            if len(results) > 5:
                result_text += f"\n... and {len(results)-5} more."
        else:
            result_text = f"No results found for '{query}' in {directory}."
            
        return [types.TextContent(type="text", text=result_text)]
        
    elif name == "write_research_log":
        entry = arguments.get("entry")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file = "RESEARCH_LOG.md"
        
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n## [{timestamp}] Researcher Log\n{entry}\n")
            return [types.TextContent(type="text", text=f"Successfully appended entry to {log_file}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Failed to write to {log_file}: {str(e)}")]
    
    raise ValueError(f"Unknown tool: {name}")

async def main():
    print("Project Ares MCP Server starting up...")
    print("Waiting for agent connection via STDIO...")
    # Run the server using standard input/output
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
