import os
import sys
import pathlib
import json
import uuid
import shutil

# Setup env
PROJECT_ROOT = pathlib.Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
sys.path.append(str(PROJECT_ROOT))

# Mock Case Dir
CASE_ROOT = PROJECT_ROOT / "mock_case_v31"
CASE_JSON = CASE_ROOT / "case.json"

from tools.case.case_manager import CaseManager
from tools.mcp.dfir_mcp_server import get_evidence_path_from_ref, audit_paths

def test_v31_guardrails():
    if CASE_ROOT.exists():
        shutil.rmtree(CASE_ROOT)
        
    os.environ["DFIR_CASE_DIR"] = str(CASE_ROOT)
    cm = CaseManager(CASE_ROOT)
    cm.init_case("test-v31")
    
    # Add dummy evidence
    src_dir = PROJECT_ROOT / "test_src_v31"
    src_dir.mkdir(exist_ok=True)
    evtx_path = src_dir / "Security.evtx"
    evtx_path.write_text("DUMMY EVTX CONTENT")
    
    cm.add_evidence(evtx_path, "evtx_1", "evtx", relpath="evtx/Security.evtx")
    
    print(f"[*] Testing Phase 31 Hardened Guardrails")
    
    # 1. Success Case
    evidence_ref = {
        "case_ref": str(CASE_JSON),
        "evidence": { "root": "staged", "relpath": "evtx/Security.evtx" }
    }
    call_id = "test-31-success"
    paths = audit_paths(call_id)
    os.makedirs(paths["base"], exist_ok=True)
    
    print("    [*] Test 1: Successful resolution and hash verification...")
    try:
        path = get_evidence_path_from_ref(evidence_ref, paths)
        print(f"    [SUCCESS] Path resolved: {path}")
        
        # Verify audit log location
        if "toolruns" in str(paths["base"]):
            print(f"    [SUCCESS] Audit logs directed to 'toolruns/'")
    except Exception as e:
        print(f"    [FAIL] Test 1 failed: {e}")

    # 2. Integrity Failure
    print("    [*] Test 2: Integrity failure (tampering)...")
    staged_path = CASE_ROOT / "evidence/staged/evtx/Security.evtx"
    if staged_path.is_symlink():
        # Need to tamper with the original
        original_path = CASE_ROOT / "evidence/original/Security.evtx"
        # Overwrite content to break hash
        original_path.write_text("TAMPERED CONTENT")
    else:
        staged_path.write_text("TAMPERED CONTENT")
        
    call_id_2 = "test-31-tamper"
    paths_2 = audit_paths(call_id_2)
    os.makedirs(paths_2["base"], exist_ok=True)
    
    try:
        get_evidence_path_from_ref(evidence_ref, paths_2)
        print(f"    [FAIL] Integrity check missed tampering!")
    except RuntimeError as e:
        if "INTEGRITY FAILURE" in str(e):
            print(f"    [SUCCESS] Caught integrity failure: {e}")
        else:
            print(f"    [FAIL] Unexpected error: {e}")

    # 3. Traversal Guard
    print("    [*] Test 3: Traversal Guard...")
    # Attempt to resolve a path outside case root using EvidenceRef structure
    # Note: resolve_evidence_path uses (base / relpath), so if relpath is "../../../dfir.py"
    # we need to see if it escapes.
    traversal_ref = {
        "case_ref": str(CASE_JSON),
        "evidence": { "root": "staged", "relpath": "../../../dfir.py" }
    }
    call_id_3 = "test-31-traversal"
    paths_3 = audit_paths(call_id_3)
    os.makedirs(paths_3["base"], exist_ok=True)
    
    try:
        get_evidence_path_from_ref(traversal_ref, paths_3)
        print(f"    [FAIL] Traversal Guard missed escape!")
    except PermissionError as e:
        if "Traversal Guard" in str(e):
            print(f"    [SUCCESS] Caught traversal attempt: {e}")
        else:
            print(f"    [FAIL] Unexpected error: {e}")

    # Cleanup
    shutil.rmtree(CASE_ROOT)
    shutil.rmtree(src_dir)

if __name__ == "__main__":
    test_v31_guardrails()
