#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# Mock environment
from tools.mcp.dfir_mcp_server import tool_read_json, symbolize_path

def test_symbolic_resolution():
    print("--- Testing Phase 32 Symbolic Resolution ---")
    
    # Use a real case from the repo for testing
    case_dir = PROJECT_ROOT / "cases" / "mills-sqlserver-2026-01"
    if not case_dir.exists():
        # Fallback to intake outputs if cases/ doesn't exist
        intake_outputs = PROJECT_ROOT / "outputs" / "intake"
        dirs = [d for d in intake_outputs.iterdir() if d.is_dir()]
        if not dirs:
            print("FAIL: No test case directory found.")
            return
        case_dir = dirs[0]
        
    print(f"[*] Testing with Case Dir: {case_dir}")
    os.environ["DFIR_CASE_DIR"] = str(case_dir)
    
    # 1. Test symbolize_path helper
    target_file = "intake.json" if (case_dir / "intake.json").exists() else "case.json"
    abs_path = case_dir / target_file
    sym_path = symbolize_path(abs_path)
    print(f"[*] Symbolized path: {sym_path}")
    if sym_path != f"CASE://{target_file}":
        print(f"FAIL: symbolize_path did not produce correct CASE:// URI. Got: {sym_path}")
        return

    # 2. Test tool_read_json with symbolic case_ref
    args = {
        "evidence_ref": {
            "case_ref": "CASE",
            "evidence": {
                "root": "case",
                "relpath": target_file
            }
        },
        "json_pointer": "/intake_id"
    }
    
    try:
        print("[*] Calling tool_read_json with case_ref='CASE'...")
        result = tool_read_json(args, {})
        print(f"[*] Result path: {result['path']}")
        print(f"[*] Result value: {result['value']}")
        
        if result['path'] != f"CASE://{target_file}":
             print(f"FAIL: Result path is not symbolized correctly. Got: {result['path']}")
             return
             
        print("SUCCESS: Symbolic resolution and symbolization confirmed.")
    except Exception as e:
        print(f"FAIL: Tool execution failed: {e}")

if __name__ == "__main__":
    test_symbolic_resolution()
