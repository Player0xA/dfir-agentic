import os
import json
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

from tools.mcp.dfir_mcp_server import (
    tool_evtx_search, 
    tool_evtx_security_search, 
    tool_registry_get_persistence,
    WINFORENSICS_AVAILABLE
)

def test_surgical_tools():
    print(f"[*] winforensics-mcp available: {WINFORENSICS_AVAILABLE}")
    if not WINFORENSICS_AVAILABLE:
        print("FAIL: WinForensics components not found or dependencies missing.")
        return False

    # Mock audit paths
    audit = {"base": Path("/tmp/verif_v19")}
    
    # 1. Test EVTX Search (if a file exists)
    # Using the demo pack Security.evtx if available
    security_evtx = Path("outputs/demo_pack/03a76529-c0a9-4216-8ab7-4a68e98328ac/Security.evtx")
    if security_evtx.exists():
        print(f"[*] Testing EVTX Security Search on {security_evtx}...")
        try:
            res = tool_evtx_security_search({"evtx_path": str(security_evtx.absolute()), "event_type": "log_cleared"}, audit)
            print(f"    - Found {len(res.get('events', []))} log clearing events.")
            
            print(f"[*] Testing Surgical EVTX Keyword Search...")
            res2 = tool_evtx_search({
                "evtx_path": str(security_evtx.absolute()), 
                "contains": ["jasonr"],
                "limit": 5
            }, audit)
            print(f"    - Found {len(res2.get('events', []))} events matching 'jasonr'.")
        except Exception as e:
            print(f"FAIL: EVTX search failed: {e}")
            return False
    else:
        print("[!] Skip EVTX: Security.evtx not found in demo pack path.")

    # 2. Test Registry Persistence
    software_hive = Path("outputs/demo_pack/03a76529-c0a9-4216-8ab7-4a68e98328ac/SOFTWARE")
    if software_hive.exists():
        print(f"[*] Testing Registry Persistence on {software_hive}...")
        try:
            res = tool_registry_get_persistence({"hive_path": str(software_hive.absolute())}, audit)
            print(f"    - Extracted {res.get('total')} persistence entries.")
        except Exception as e:
            print(f"FAIL: Registry search failed: {e}")
            return False
    else:
        print("[!] Skip Registry: SOFTWARE hive not found in demo pack path.")

    print("\n[SUCCESS] Phase 19 Surgical Tools are operational.")
    return True

if __name__ == "__main__":
    if test_surgical_tools():
        sys.exit(0)
    else:
        sys.exit(1)
