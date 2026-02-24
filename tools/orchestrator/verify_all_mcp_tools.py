import os
import sys
import json
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

# Force DFIR_CASE_DIR to allow demo pack access
demo_case = PROJECT_ROOT / "outputs/demo_pack/03a76529-c0a9-4216-8ab7-4a68e98328ac"
os.environ["DFIR_CASE_DIR"] = str(demo_case)

# Mock Audit Support
def mock_audit():
    call_id = str(uuid.uuid4())
    base = Path(f"/tmp/audit_{call_id}")
    base.mkdir(parents=True, exist_ok=True)
    return {
        "base": base,
        "stdout": base / "stdout.log",
        "stderr": base / "stderr.log"
    }

def test_tool(name, func, args):
    print(f"[*] Testing {name}...", end=" ", flush=True)
    try:
        audit = mock_audit()
        res = func(args, audit)
        print("PASS")
        return True, res
    except Exception as e:
        print(f"FAIL ({e})")
        return False, str(e)

def run_suite():
    print("="*60)
    print("      MCP TOOL SUITE INTEGRITY VERIFICATION (V20)      ")
    print("="*60)
    
    # Delayed import to ensure sys.path and env are applied
    from tools.mcp import dfir_mcp_server
    
    # 1. Core Tools (Disk/Triage)
    print(f"\n[PHASE 1: CORE DISK TOOLS]")
    
    # Identify Evidence
    test_tool("dfir.identify_evidence", dfir_mcp_server.tool_identify_evidence, {
        "path": str(demo_case)
    })
    
    # List Dir
    test_tool("dfir.list_dir", dfir_mcp_server.tool_list_dir, {
        "path": str(demo_case)
    })

    # 2. Surgical Tools (Phase 19)
    print(f"\n[PHASE 2: SURGICAL FORENSICS]")
    if dfir_mcp_server.WINFORENSICS_AVAILABLE:
        # Check EVTX
        sec_path = demo_case / "Security.evtx"
        if sec_path.exists():
            test_tool("dfir.evtx_security_search", dfir_mcp_server.tool_evtx_security_search, {
                "evtx_path": str(sec_path),
                "event_type": "logon",
                "limit": 1
            })
        else:
            print(" [SKIP] dfir.evtx_security_search (Security.evtx missing in demo pack)")
            
        # Check Registry
        # Note: Demo pack usually doesn't have raw hives unless generated
        soft_path = demo_case / "SOFTWARE"
        if soft_path.exists():
            test_tool("dfir.registry_get_persistence", dfir_mcp_server.tool_registry_get_persistence, {
                "hive_path": str(soft_path)
            })
        else:
            print(" [SKIP] dfir.registry_get_persistence (SOFTWARE hive missing in demo pack)")
    else:
        print(" [FAIL] Surgical tools unavailable (WINFORENSICS_AVAILABLE=False)")

    # 3. Plaso Tools
    print(f"\n[PHASE 3: PLASO TIMELINE TOOLS]")
    plaso_path = demo_case / "case.plaso"
    if plaso_path.exists():
        test_tool("dfir.query_super_timeline", dfir_mcp_server.tool_query_super_timeline, {
            "plaso_file": str(plaso_path),
            "contains": ["jasonr"],
            "limit": 1
        })
    else:
         print(" [SKIP] dfir.query_super_timeline (case.plaso missing)")

    print("\n" + "="*60)
    print(" Audit Complete.")
    print(" (X) Note: If Surgical tools show FAIL due to Evtx views, check site-packages layout.")
    print(" (X) Suggestion: DO NOT install new tools. Use existing 'pip install' on host if needed.")

if __name__ == "__main__":
    run_suite()
