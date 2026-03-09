import os
import json
import unittest
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch

class TestPhase15Epistemic(unittest.TestCase):
    def test_case_notes_validation_positive(self):
        """Test valid structured case notes."""
        valid_args = {
            "claims": [
                {
                    "claim_id": "C1",
                    "type": "OBSERVATION",
                    "statement": "Found 4624 logon for user jasonr.",
                    "evidence_refs": ["EVT-1234"],
                    "confidence": "High",
                    "status": "Confirmed"
                }
            ],
            "next_steps": ["Investigate PID 5760"]
        }
        is_valid, err = orch.validate_case_notes(valid_args)
        self.assertTrue(is_valid, f"Should be valid: {err}")

    def test_case_notes_validation_epistemic_failure(self):
        """Test 'attacker' keyword enforcement (must be HYPOTHESIS)."""
        invalid_args = {
            "claims": [
                {
                    "claim_id": "C2",
                    "type": "OBSERVATION",
                    "statement": "The attacker used psexec.",
                    "evidence_refs": ["EVT-999"],
                    "status": "Open"
                }
            ],
            "next_steps": []
        }
        is_valid, err = orch.validate_case_notes(invalid_args)
        self.assertFalse(is_valid)
        self.assertIn("Epistemic Violation", err)
        self.assertIn("not marked as 'HYPOTHESIS'", err)

    def test_case_notes_validation_evidence_failure(self):
        """Test HYPOTHESIS enforcement (must have evidence_refs)."""
        invalid_args = {
            "claims": [
                {
                    "claim_id": "C3",
                    "type": "HYPOTHESIS",
                    "statement": "Possible credential compromise.",
                    "evidence_refs": [],
                    "status": "Open"
                }
            ],
            "next_steps": []
        }
        is_valid, err = orch.validate_case_notes(invalid_args)
        self.assertFalse(is_valid)
        self.assertIn("must cite specific 'evidence_refs'", err)

    def test_new_tools_presence(self):
        """Verify new V15 tools exist in server discovery."""
        from tools.mcp.dfir_mcp_server import TOOLS
        tool_names = [t["name"] for t in TOOLS]
        self.assertIn("dfir.correlate_pivot@1", tool_names)
        self.assertIn("dfir.pivot_ladder@1", tool_names)

if __name__ == "__main__":
    # Mocking DFIR_CASE_DIR for import side-effects if any
    os.environ["DFIR_CASE_DIR"] = "/tmp"
    unittest.main()
