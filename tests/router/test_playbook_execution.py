import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def run_cmd(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True, cwd=str(PROJECT_ROOT))
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def test_playbook_execution_and_gap():
    print("--- Testing Playbook Execution & GAP Handling ---")
    
    test_case_dir = PROJECT_ROOT / "outputs" / "test-playbook-case-001"
    if test_case_dir.exists():
        shutil.rmtree(test_case_dir)
        
    # 1. Initialize case
    rc, out, err = run_cmd(["python3", "tools/case/init_case.py", "--case-id", "test-playbook-case-001", "--root", "outputs"])
    assert rc == 0, f"Init case failed: {err}"
    
    # 2. Modify case.json to include a dummy 'staged' evidence
    case_json_path = test_case_dir / "case.json"
    case_meta = json.loads(case_json_path.read_text())
    
    # create dummy evtx dir
    dummy_evtx_dir = test_case_dir / "evidence" / "staged" / "dummy_logs"
    dummy_evtx_dir.mkdir(parents=True, exist_ok=True)
    
    case_meta["evidence"].append({
        "evidence_id": "dummy-001",
        "type": "windows_evtx_dir",
        "root": "staged",
        "relpath": "dummy_logs",
        "original_name": "dummy_logs",
        "added_utc": "2026-02-24T00:00:00Z"
    })
    write_json(case_json_path, case_meta)
    
    # Ensure case_notes.json exists
    case_notes_path = test_case_dir / "case_notes.json"
    if not case_notes_path.exists():
        write_json(case_notes_path, {
            "case_id": "test-playbook-case-001",
            "claims": []
        })

    # 3. Run dispatch_intake.py
    # This will attempt 'initial_access_v1' which runs chainsaw -> hayabusa -> plaso
    # They should fail because the directory is empty/invalid, meaning GAP claims will be made.
    rc, out, err = run_cmd([
        "python3", "tools/router/dispatch_intake.py", 
        "--intake-json", str(case_json_path),
        "--playbook", "initial_access_v1"
    ])
    
    # Should not crash (rc=0)
    assert rc == 0, f"Dispatch crashed: {err}\nOut: {out}"
    
    # 4. Verify dispatch.json
    dispatch_json_path = test_case_dir / "dispatch.json"
    assert dispatch_json_path.exists(), "dispatch.json not generated"
    dispatch_data = json.loads(dispatch_json_path.read_text())
    
    steps = dispatch_data["result"].get("steps", [])
    assert len(steps) > 0, "No steps recorded in dispatch.json"
    
    print(f"[*] Step History: {steps}")
    # Verify order enforcing (chainsaw_evtx, hayabusa_evtx, plaso_evtx)
    assert "chainsaw_evtx" in steps[0], f"Step 1 was down as {steps[0]}"
    assert "hayabusa_evtx" in steps[1], f"Step 2 was down as {steps[1]}"
    
    # 5. Verify GAP handling
    notes_data = json.loads(case_notes_path.read_text())
    gaps = [c for c in notes_data.get("claims", []) if c.get("type") == "GAP"]
    
    assert len(gaps) > 0, "GAP claims were not generated on failure"
    print(f"[*] GAP Claims Generated: {len(gaps)}")
    for gap in gaps:
        print(f"  - {gap['focus']}: {gap['content']}")
        assert gap["impact"] == "CRITICAL", "GAP impact should be CRITICAL"
    
if __name__ == "__main__":
    try:
        test_playbook_execution_and_gap()
        print("[SUCCESS] Playbook Execution & GAP Integration Test passed.")
    except AssertionError as e:
        print(f"[FAIL] {e}")
        sys.exit(1)
