import os
import sys
import json
import subprocess
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# Mock data
MOCK_INTAKE = {
    "case_id": "test-playbook-001",
    "evidence_roots": {"original": "/tmp", "staged": "/tmp"},
    "created_utc": "2026-02-24T00:00:00Z",
    "evidence": [{"evidence_id": "evtx-001", "type": "windows_evtx_dir", "root": "staged", "relpath": "test_logs"}]
}

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)
        
def run_cmd(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True, cwd=str(PROJECT_ROOT))
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def test_playbook_selection():
    print("--- Testing Playbook Selection ---")
    intake_path = PROJECT_ROOT / "tests" / "mock_intake.json"
    write_json(intake_path, MOCK_INTAKE)
    
    # Test 1: 'tamper' keyword -> log_tampering_v1
    rc, out, err = run_cmd(["python3", "tools/router/select_agent.py", "--intake-json", str(intake_path), "--task", "Check for tamper logs"])
    assert rc == 0, f"Error: {err}"
    result = json.loads(out)
    assert result["selected_playbook"] == "log_tampering_v1", f"Failed: {result}"
    print("[*] log_tampering_v1 selection passed.")

    # Test 2: 'lateral' keyword -> lateral_movement_v1
    rc, out, err = run_cmd(["python3", "tools/router/select_agent.py", "--intake-json", str(intake_path), "--task", "Trace lateral movement via RDP"])
    assert rc == 0, f"Error: {err}"
    result = json.loads(out)
    assert result["selected_playbook"] == "lateral_movement_v1", f"Failed: {result}"
    print("[*] lateral_movement_v1 selection passed.")
    
    # Test 3: 'persistence' keyword -> persistence_v1
    rc, out, err = run_cmd(["python3", "tools/router/select_agent.py", "--intake-json", str(intake_path), "--task", "Detect persistence via run keys"])
    assert rc == 0, f"Error: {err}"
    result = json.loads(out)
    assert result["selected_playbook"] == "persistence_v1", f"Failed: {result}"
    print("[*] persistence_v1 selection passed.")
    
    # Test 4: Default -> initial_access_v1
    rc, out, err = run_cmd(["python3", "tools/router/select_agent.py", "--intake-json", str(intake_path)])
    assert rc == 0, f"Error: {err}"
    result = json.loads(out)
    assert result["selected_playbook"] == "initial_access_v1", f"Failed: {result}"
    print("[*] Default initial_access_v1 selection passed.")

    if intake_path.exists():
        intake_path.unlink()

if __name__ == "__main__":
    try:
        test_playbook_selection()
        print("[SUCCESS] Unit tests for selection passed.")
    except AssertionError as e:
        print(f"[FAIL] {e}")
        sys.exit(1)
