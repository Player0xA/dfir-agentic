#!/usr/bin/env python3
"""
Verification script for Multi-Server MCP Bundle.
Tests routing to both 'dfir' and 'win' providers.
"""
import sys
import json
from pathlib import Path

# Add orchestrator to path
sys.path.append(str(Path(__file__).parent))
import deepseek_orchestrator

def test_tool(name, args):
    print(f"\n--- Testing Tool: {name} ---")
    try:
        result = deepseek_orchestrator.mcp_tools_call(name, args)
        print("SUCCESS! Result preview:")
        print(json.dumps(result, indent=2)[:500] + "...")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    print("Starting Multi-Server MCP Verification...")
    
    # 1. Test DFIR Server (Core)
    test_tool("dfir.list_dir@1", {"path": "."})
    
    # 2. Test WinForensics Server (Submodule)
    test_tool("evtx_explain_event_id", {"event_id": 4624})
