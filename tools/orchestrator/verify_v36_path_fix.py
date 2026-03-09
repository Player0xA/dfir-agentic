#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# Mock DFIR_CASE_DIR
os.environ["DFIR_CASE_DIR"] = "/tmp/mock-case"
mock_case_dir = Path("/tmp/mock-case")
mock_case_dir.mkdir(parents=True, exist_ok=True)

from tools.mcp.dfir_mcp_server import resolve_evidence

def test_v36_path_resolution():
    print("--- Testing Phase 36 Path Resolution Fix ---")
    
    # Test Case 1: CASE:// prefix
    path_1 = "CASE://case_summary.md"
    resolved_1 = resolve_evidence(path_1)
    expected_1 = (mock_case_dir / "case_summary.md").resolve()
    print(f"[*] Case 1: Resolving '{path_1}' -> {resolved_1}")
    if resolved_1 != expected_1:
        print(f"FAIL: Case 1 failed. Got: {resolved_1}, Expected: {expected_1}")
        return

    # Test Case 2: CASE: prefix (no slashes)
    path_2 = "CASE:evidence/staged/logs"
    resolved_2 = resolve_evidence(path_2)
    expected_2 = (mock_case_dir / "evidence/staged/logs").resolve()
    print(f"[*] Case 2: Resolving '{path_2}' -> {resolved_2}")
    if resolved_2 != expected_2:
        print(f"FAIL: Case 2 failed. Got: {resolved_2}, Expected: {expected_2}")
        return

    # Test Case 3: CASE:// with multiple slashes
    path_3 = "CASE:///case_findings.json"
    resolved_3 = resolve_evidence(path_3)
    expected_3 = (mock_case_dir / "case_findings.json").resolve()
    print(f"[*] Case 3: Resolving '{path_3}' -> {resolved_3}")
    if resolved_3 != expected_3:
        print(f"FAIL: Case 3 failed. Got: {resolved_3}, Expected: {expected_3}")
        return

    print("SUCCESS: Phase 36 Path Resolution Fix verified.")

if __name__ == "__main__":
    try:
        test_v36_path_resolution()
    finally:
        # Cleanup
        if (mock_case_dir / "case_summary.md").exists():
            (mock_case_dir / "case_summary.md").unlink()
        # Not deleting /tmp/mock-case easily to avoid risk, but it's fine for a test.
