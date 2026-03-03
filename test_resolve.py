import os
import sys
from pathlib import Path

# Setup context
os.environ["DFIR_CASE_DIR"] = str(Path.cwd() / "outputs" / "intake" / "mock-case-id")

from tools.mcp.dfir_mcp_server import resolve_evidence, resolve_evidence_path

# 1. Test NoneType error in resolve_evidence_path when reading from a fake intake.json
case_dir = Path(os.environ["DFIR_CASE_DIR"])
case_dir.mkdir(parents=True, exist_ok=True)
intake_path = case_dir / "intake.json"
intake_path.write_text('{"intake_id": "mock-case-id"}')

try:
    print("Testing resolve_evidence_path...")
    path = resolve_evidence_path("CASE", "staged", "")
    print(f"SUCCESS: {path}")
except Exception as e:
    print(f"FAILED: {e}")

# 2. Test Path Doubling in resolve_evidence
try:
    print("\nTesting resolve_evidence (Path Doubling)...")
    doubled_path = f"outputs/intake/mock-case-id/case_findings.json"
    resolved = resolve_evidence(doubled_path)
    print(f"SUCCESS: {resolved}")
except Exception as e:
    print(f"FAILED: {e}")

