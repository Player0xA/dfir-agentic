import os
import sys
import shutil
import pathlib
import json

# Setup env
PROJECT_ROOT = pathlib.Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
sys.path.append(str(PROJECT_ROOT))

from tools.case.case_manager import CaseManager

def test_v27_staging():
    test_root = PROJECT_ROOT / "test_case_v27"
    if test_root.exists():
        shutil.rmtree(test_root)
        
    cm = CaseManager(test_root)
    
    print(f"[*] Initializing case at {test_root}")
    cm.init_case("test-case-27")
    
    # Create dummy source evidence
    src_dir = PROJECT_ROOT / "test_src_staging"
    src_dir.mkdir(exist_ok=True)
    log_file = src_dir / "Security.evtx"
    log_file.write_text("DUMMY EVTX CONTENT")
    
    print("\n[*] Adding evidence with deterministic staging...")
    cm.add_evidence(src_dir, "evtx_dir_001", "evtx_dir", relpath="evtx/Logs")
    
    # 1. Verify Manifests exist
    orig_manifest = test_root / "manifests/evidence.manifest.json"
    staged_manifest = test_root / "manifests/staged.manifest.json"
    
    if orig_manifest.exists() and staged_manifest.exists():
        print("    [SUCCESS] Created evidence.manifest.json and staged.manifest.json")
    else:
        print("    [FAIL] Manifests missing")
        
    # 2. Verify Hashes in Manifest
    orig_data = json.loads(orig_manifest.read_text(encoding="utf-8"))
    staged_data = json.loads(staged_manifest.read_text(encoding="utf-8"))
    
    # Find Security.evtx in manifests
    orig_file = next((f for f in orig_data["files"] if "Security.evtx" in f["relpath"]), None)
    staged_file = next((f for f in staged_data["files"] if "Security.evtx" in f["relpath"]), None)
    
    if orig_file and staged_file:
        print(f"    [SUCCESS] Tracked Security.evtx in both manifests")
        if orig_file["sha256"] == staged_file["sha256"]:
            print(f"    [SUCCESS] Hash verified: {orig_file['sha256']}")
        else:
            print(f"    [FAIL] Hash mismatch!")
    else:
        print("    [FAIL] Security.evtx not found in manifests")

    # 3. Verify case.json reference
    case_json = test_root / "case.json"
    case_data = json.loads(case_json.read_text(encoding="utf-8"))
    evidence_item = case_data["evidence"][0]
    
    if "manifest_refs" in evidence_item:
        orig_ref = evidence_item["manifest_refs"]["original"]
        if orig_ref == "manifests/evidence.manifest.json":
            print("    [SUCCESS] case.json references the authoritative manifest")
    else:
        print("    [FAIL] case.json missing manifest_refs")

    # Cleanup
    shutil.rmtree(test_root)
    shutil.rmtree(src_dir)

if __name__ == "__main__":
    test_v27_staging()
