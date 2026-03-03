import sys
import json
import os
from pathlib import Path
sys.path.append(str(Path.cwd()))
from tools.orchestrator.deepseek_orchestrator import mcp_list_tools, _close_all_mcp_clients

try:
    print("Testing DFIR tools:")
    dfir_tools = mcp_list_tools("dfir")
    print(f"Found {len(dfir_tools)} tools")
    
    print("\nTesting MEM tools:")
    mem_tools = mcp_list_tools("mem")
    print(f"Found {len(mem_tools)} tools")
    for t in mem_tools:
        print(f"- {t['name']}")
finally:
    _close_all_mcp_clients()
