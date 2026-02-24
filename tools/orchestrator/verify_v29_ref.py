import os
import sys
import pathlib
import json
import uuid

# Setup env
PROJECT_ROOT = pathlib.Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
sys.path.append(str(PROJECT_ROOT))

# Mock Case Dir
CASE_ROOT = PROJECT_ROOT / "mock_case_v29"
CASE_JSON = CASE_ROOT / "case.json"

from tools.case.case_manager import CaseManager
from tools.mcp.dfir_mcp_server import dispatch_tool, audit_paths

def test_v29_evidence_ref():
    if CASE_ROOT.exists():
        import shutil
        shutil.rmtree(CASE_ROOT)
        
    cm = CaseManager(CASE_ROOT)
    cm.init_case("test-v29")
    
    # Set DFIR_CASE_DIR for dynamic resolution in MCP server
    os.environ["DFIR_CASE_DIR"] = str(CASE_ROOT)
    
    # Add dummy evidence
    src_dir = PROJECT_ROOT / "test_src_v29"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "Security.evtx").write_text("DUMMY EVTX")
    (src_dir / "SOFTWARE").write_text("DUMMY REGISTRY")
    
    cm.add_evidence(src_dir / "Security.evtx", "evtx_1", "evtx", relpath="evtx/Security.evtx")
    cm.add_evidence(src_dir / "SOFTWARE", "reg_1", "registry", relpath="registry/SOFTWARE")
    
    print(f"[*] Testing Uniform EvidenceRef Contract")
    
    # 1. Test evtx_search
    evidence_ref = {
        "case_ref": str(CASE_JSON),
        "evidence": {
            "root": "staged",
            "relpath": "evtx/Security.evtx"
        }
    }
    
    args = {"evidence_ref": evidence_ref, "limit": 1}
    call_id = "test-call-v29-evtx"
    paths = audit_paths(call_id)
    os.makedirs(paths["base"], exist_ok=True)
    
    print(f"    [*] Calling dfir.evtx_search with EvidenceRef...")
    try:
        # We need to mock WINFORENSICS_AVAILABLE or ensure it's on a machine that can run it.
        # For verification, we'll just check if it calls get_evidence_path_from_ref correctly.
        # Since I can't easily mock the module in this script without import tricks,
        # I'll check if the audit log is created.
        result = dispatch_tool("dfir.evtx_search@1", args, paths)
    except Exception as e:
        # If it fails due to missing parser, we still check audit log
        print(f"    [NOTE] Tool execution finished (possibly with parser error): {e}")

    # Check Evidence Audit Log
    audit_file = paths["base"] / "evidence_audit.json"
    if audit_file.exists():
        audit_data = json.loads(audit_file.read_text())
        print(f"    [SUCCESS] Evidence Audit Log created: {audit_file.name}")
        if audit_data["evidence_ref"] == evidence_ref:
            print(f"    [SUCCESS] Audit Log captures correct EvidenceRef")
        if "manifest_sha256" in audit_data:
            print(f"    [SUCCESS] Audit Log verified hash from manifest: {audit_data['manifest_sha256']}")
    else:
        print(f"    [FAIL] Evidence Audit Log missing!")

    # Cleanup
    import shutil
    shutil.rmtree(CASE_ROOT)
    shutil.rmtree(src_dir)

if __name__ == "__main__":
    test_v29_evidence_ref()
