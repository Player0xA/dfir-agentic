import os
import sys
from pathlib import Path
import shutil

# Mock environment
PROJECT_ROOT = Path("/Users/marianosanchezrojas/dfir-agentic/dfir-agentic")
DFIR_CASE_DIR = str(PROJECT_ROOT / "mock_case")

# Setup sys.path to find our server
sys.path.append(str(PROJECT_ROOT))

# Import the resolvers
from tools.mcp.dfir_mcp_server import resolve_internal, resolve_evidence

def test_context_resolution():
    print(f"[*] Project Root: {PROJECT_ROOT}")
    
    # ---------------------------------------------------------
    # Test 1: Internal Resolution (must anchor to PROJECT_ROOT)
    # ---------------------------------------------------------
    rel_internal = "outputs/intake.json"
    resolved_internal = resolve_internal(rel_internal)
    print(f"\n[1] Internal (Relative: {rel_internal})")
    print(f"    Resolved: {resolved_internal}")
    
    expected_internal = PROJECT_ROOT / rel_internal
    if resolved_internal == expected_internal:
        print("    [SUCCESS] Correctly anchored to PROJECT_ROOT")
    else:
        print(f"    [FAIL] Expected {expected_internal}")

    # ---------------------------------------------------------
    # Test 2: Evidence Resolution (must anchor to CASE_PATH)
    # ---------------------------------------------------------
    # Create a dummy evidence file under a mock case dir
    mock_case_root = Path(DFIR_CASE_DIR)
    mock_case_root.mkdir(parents=True, exist_ok=True)
    rel_evidence = "evtx/Logs/Security.evtx"
    real_evidence_path = mock_case_root / rel_evidence
    real_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    real_evidence_path.touch()
    
    os.environ["DFIR_CASE_DIR"] = DFIR_CASE_DIR
    
    resolved_evidence = resolve_evidence(rel_evidence)
    print(f"\n[2] Evidence (Relative: {rel_evidence} | CASE_DIR: {mock_case_root})")
    print(f"    Resolved: {resolved_evidence}")
    
    if resolved_evidence == real_evidence_path.resolve():
        print("    [SUCCESS] Correctly anchored to DFIR_CASE_DIR")
    else:
        print(f"    [FAIL] Expected {real_evidence_path.resolve()}")

    # ---------------------------------------------------------
    # Test 3: Hallucination Healer (Corrupted Absolute Path)
    # ---------------------------------------------------------
    # Hallucinated: /home/nevermore/dfir-agentic/outputs/intake/cases/intake/evtx/Logs/Security.evtx
    # We want it to resolve to PROJECT_ROOT / "outputs/intake/cases/intake/evtx/Logs/Security.evtx" if it exists
    hallucinated_tail = "outputs/intake/cases/intake/evtx/Logs/Security.evtx"
    real_healed_file = PROJECT_ROOT / hallucinated_tail
    real_healed_file.parent.mkdir(parents=True, exist_ok=True)
    real_healed_file.touch()
    
    bad_path = "/home/nevermore/dfir-agentic/outputs/intake/cases/intake/evtx/Logs/Security.evtx"
    print(f"\n[3] Hallucination Healer (Bad: {bad_path})")
    resolved_healed = resolve_evidence(bad_path)
    print(f"    Resolved: {resolved_healed}")
    
    if resolved_healed == real_healed_file.resolve():
        print("    [SUCCESS] Hallucinated prefix stripped and re-anchored to project.")
    else:
        print(f"    [FAIL] Did not resolve to {real_healed_file.resolve()}")

    # Cleanup
    real_evidence_path.unlink()
    real_healed_file.unlink()
    shutil.rmtree(mock_case_root)

if __name__ == "__main__":
    test_context_resolution()
