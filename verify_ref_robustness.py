#!/usr/bin/env python3
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from tools.mcp.dfir_mcp_server import tool_list_dir, tool_evtx_search, get_case_dir

def test_robustness():
    # Setup mock environment
    case_dir = PROJECT_ROOT / "outputs" / "test-playbook-case-001"
    os.environ["DFIR_CASE_DIR"] = str(case_dir)
    
    print(f"[*] Testing with DFIR_CASE_DIR: {case_dir}")
    
    # 1. Test list_dir with missing relpath
    print("[*] Test 1: list_dir with missing relpath")
    try:
        args = {
            "evidence_ref": {
                "case_ref": "CASE",
                "evidence": {"root": "staged"}
            }
        }
        res = tool_list_dir(args, {})
        print(f"[+] Success: Found {len(res['entries'])} entries in staged root.")
    except Exception as e:
        print(f"[-] Failure: {e}")

    # 2. Test evtx_search with missing case_ref
    print("[*] Test 2: evtx_search with missing case_ref")
    try:
        # We need a real file to search, or at least a path that resolves
        args = {
            "evidence_ref": {
                "evidence": {
                    "root": "staged",
                    "relpath": "Logs/Security.evtx"
                }
            },
            "limit": 1
        }
        # This will fail on actual search if file missing, but we want to see if it resolves path
        from tools.mcp.dfir_mcp_server import get_evidence_path_from_ref
        path = get_evidence_path_from_ref(args["evidence_ref"], {})
        print(f"[+] Success: Resolved path: {path}")
    except Exception as e:
        print(f"[-] Failure: {e}")

    # 3. Test with None ref (should still raise ValueError as per design, but specific one)
    print("[*] Test 3: get_evidence_path_from_ref(None)")
    try:
        from tools.mcp.dfir_mcp_server import get_evidence_path_from_ref
        get_evidence_path_from_ref(None, {})
    except ValueError as e:
        print(f"[+] Success: Caught expected ValueError: {e}")
    except Exception as e:
        print(f"[-] Failure: Caught unexpected exception: {type(e)} {e}")

if __name__ == "__main__":
    test_robustness()
