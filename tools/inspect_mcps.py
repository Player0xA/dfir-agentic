#!/usr/bin/env python3
import os
import re
from pathlib import Path

# MCP Tool Inspection Script for dfir-agentic
# Scans the three primary MCP servers and lists their available tools.

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MCP_CONFIGS = [
    {
        "id": "dfir",
        "name": "DFIR Core MCP",
        "path": PROJECT_ROOT / "tools" / "mcp" / "dfir_mcp_server.py",
        "type": "native_tools_list"
    },
    {
        "id": "win",
        "name": "Windows Triage MCP",
        "path": PROJECT_ROOT / "tools" / "mcp" / "mcp-windows" / "winforensics-mcp" / "winforensics_mcp" / "server.py",
        "type": "fastmcp_decorators"
    },
    {
        "id": "mem",
        "name": "Memory Forensics MCP",
        "path": PROJECT_ROOT / "tools" / "mcp" / "memory" / "mem_forensics-mcp" / "mem_forensics_mcp" / "server.py",
        "type": "fastmcp_decorators"
    }
]

def extract_tools_from_file(config):
    path = config["path"]
    if not path.exists():
        return [f"ERR: File not found at {path}"]
    
    content = path.read_text(encoding="utf-8")
    tools = []
    
    if config["type"] == "native_tools_list":
        # Look for "name": "..." entries inside the TOOLS list
        matches = re.findall(r'"name":\s*"([^"]+)"', content)
        for m in matches:
            if m not in tools:
                tools.append(m)
    
    elif config["type"] == "fastmcp_decorators":
        # Strategy 1: Look for FastMCP-style @server.tool() decorators
        matches = re.findall(r'@server\.tool\((?:name\s*=\s*"([^"]+)")?', content)
        for m in matches:
            if m: tools.append(m)
        
        # Strategy 2: Look for manual Tool(name="...") instantiations (for win/mem servers)
        manual_matches = re.findall(r'Tool\(\s*name\s*=\s*"([^"]+)"', content)
        for m in manual_matches:
            if m not in tools:
                tools.append(m)
        
        # Strategy 3: Specific fallback for Memory server which might have them in a list
        if config["id"] == "mem":
            # Search for mem. prefix in strings
            mem_matches = re.findall(r'"(mem\.[^"]+)"', content)
            tools.extend(mem_matches)
    
    return sorted(list(set(tools)))

def main():
    print("=" * 60)
    print("  DFIR-Agentic: Forensic MCP Tool Discovery")
    print("=" * 60)
    
    total_found = 0
    for config in MCP_CONFIGS:
        print(f"\n[+] {config['name']} ({config['id']})")
        print("-" * 60)
        tools = extract_tools_from_file(config)
        if not tools:
            print("  (No tools detected via inspection)")
        else:
            for t in tools:
                print(f"  - {t}")
            total_found += len(tools)
    
    print("\n" + "=" * 60)
    print(f"  Discovery complete. Total Tools: {total_found}")
    print("=" * 60)

if __name__ == "__main__":
    main()
