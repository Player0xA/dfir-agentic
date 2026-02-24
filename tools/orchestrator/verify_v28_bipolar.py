import os
import sys
import pathlib
import json

# Setup env
PROJECT_ROOT = pathlib.Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
sys.path.append(str(PROJECT_ROOT))

# Mock Case Dir
CASE_DIR = PROJECT_ROOT / "mock_case_v28"
CASE_JSON = CASE_DIR / "case.json"

from tools.mcp.dfir_mcp_server import resolve_project_path, resolve_evidence_path

def test_v28_bipolar_resolution():
    if CASE_DIR.exists():
        import shutil
        shutil.rmtree(CASE_DIR)
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create evidence roots
    staged_dir = CASE_DIR / "evidence/staged/evtx/Logs"
    staged_dir.mkdir(parents=True, exist_ok=True)
    (staged_dir / "Security.evtx").touch()
    
    case_data = {
        "case_id": "test-v28",
        "case_root": str(CASE_DIR),
        "evidence_roots": {
            "original": str(CASE_DIR / "evidence/original"),
            "staged": str(CASE_DIR / "evidence/staged")
        }
    }
    CASE_JSON.write_text(json.dumps(case_data, indent=2))
    
    print(f"[*] Testing Bipolar Resolution")
    
    # 1. Project Path
    p_path = "contracts/case.schema.json"
    resolved_p = resolve_project_path(p_path)
    if resolved_p == (PROJECT_ROOT / p_path).resolve():
        print(f"    [SUCCESS] resolve_project_path: {p_path} -> {resolved_p}")
    else:
        print(f"    [FAIL] resolve_project_path failed")
        
    # 2. Evidence Path (Staged)
    rel_p = "evtx/Logs/Security.evtx"
    resolved_e = resolve_evidence_path(CASE_JSON, "staged", rel_p)
    if resolved_e == (staged_dir / "Security.evtx").resolve():
        print(f"    [SUCCESS] resolve_evidence_path: {rel_p} -> {resolved_e}")
    else:
        print(f"    [FAIL] resolve_evidence_path failed: {resolved_e}")

    # Cleanup
    import shutil
    shutil.rmtree(CASE_DIR)

if __name__ == "__main__":
    test_v28_bipolar_resolution()
