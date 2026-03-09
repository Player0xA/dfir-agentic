import os
import sys
import shutil
import pathlib
import json

# Setup env
PROJECT_ROOT = pathlib.Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
sys.path.append(str(PROJECT_ROOT))

from tools.case.case_manager import CaseManager

def test_v26_layout():
    test_root = PROJECT_ROOT / "test_case_v26"
    if test_root.exists():
        shutil.rmtree(test_root)
        
    cm = CaseManager(test_root)
    
    print(f"[*] Initializing case at {test_root}")
    cm.init_case("test-case-26")
    
    # Verify directories
    expected = ["evidence/original", "evidence/staged", "outputs", "manifests", "logs"]
    for d in expected:
        p = test_root / d
        if p.is_dir():
            print(f"    [SUCCESS] Created {d}")
        else:
            print(f"    [FAIL] Missing {d}")

    # Create dummy source evidence
    src_dir = PROJECT_ROOT / "test_src_logs"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "Security.evtx").touch()
    
    print("\n[*] Adding evidence to case...")
    cm.add_evidence(src_dir, "evtx_dir_001", "evtx_dir", relpath="evtx/Logs")
    
    # 1. Verify Original (Immutable Copy)
    original_path = test_root / "evidence/original/test_src_logs/Security.evtx"
    if original_path.exists():
        print("    [SUCCESS] Evidence copied to original/")
    else:
        print("    [FAIL] Evidence missing in original/")
        
    # 2. Verify Staged (Normalized / Symlink)
    staged_path = test_root / "evidence/staged/evtx/Logs/Security.evtx"
    if staged_path.exists():
        print("    [SUCCESS] Evidence accessible in staged/evtx/Logs")
        if (test_root / "evidence/staged/evtx/Logs").is_symlink():
            print("    [SUCCESS] Staged entry is a symlink")
    else:
        print("    [FAIL] Evidence missing in staged/")

    # 3. Verify Authoritative case.json
    case_json = test_root / "case.json"
    data = json.loads(case_json.read_text(encoding="utf-8"))
    
    if data["case_id"] == "test-case-26":
        print("    [SUCCESS] case.json has correct case_id")
        
    evidence_item = data["evidence"][0]
    if evidence_item["evidence_id"] == "evtx_dir_001" and evidence_item["relpath"] == "evtx/Logs":
        print("    [SUCCESS] case.json tracks evidence with Logical ID and relpath")
    else:
        print(f"    [FAIL] case.json evidence data unexpected: {evidence_item}")

    # Cleanup
    shutil.rmtree(test_root)
    shutil.rmtree(src_dir)

if __name__ == "__main__":
    test_v26_layout()
