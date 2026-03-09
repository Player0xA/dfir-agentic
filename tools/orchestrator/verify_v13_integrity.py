import os
import json
import unittest
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch

class TestPhase13Integrity(unittest.TestCase):
    def test_rca_schema_validation_positive(self):
        """Verifies that a valid RCA block passes validation."""
        valid_rca = {
            "summary": "The security logs were cleared to hide traces of SMB logons.",
            "root_cause": "External credential compromise of user jasonr.",
            "confidence": "Medium",
            "claims": [
                {
                    "claim": "Security logs cleared via PID 5760.",
                    "supporting_evidence": ["EVT_1102", "TIMELINE_001"]
                }
            ],
            "unknowns": ["Provenance of PID 5760 is unresolved."],
            "mitre_attack_mapping": [
                {
                    "technique_id": "T1070.001",
                    "tactic": "Defense Evasion",
                    "evidence": "Event ID 1102 detected."
                }
            ],
            "assessment": "The proximity of SMB logons suggests a linked attack chain."
        }
        
        valid_tool_call = {
            "function": {
                "name": "dfir__update_case_notes__v1",
                "arguments": json.dumps({"notes": f"```json\n{json.dumps(valid_rca)}\n```"})
            }
        }
        
        history = [{"role": "assistant", "tool_calls": [valid_tool_call]}]
        is_valid, err = orch.check_for_rca(history)
        self.assertTrue(is_valid, f"Expected valid RCA to pass, but failed: {err}")

    def test_rca_schema_validation_missing_fields(self):
        """Verifies that an RCA missing required fields fails validation."""
        invalid_rca = {
            "summary": "Missing root_cause and claims",
            "confidence": "Low"
        }
        
        invalid_tool_call = {
            "function": {
                "name": "dfir__update_case_notes__v1",
                "arguments": json.dumps({"notes": f"```json\n{json.dumps(invalid_rca)}\n```"})
            }
        }
        
        history = [{"role": "assistant", "tool_calls": [invalid_tool_call]}]
        is_valid, err = orch.check_for_rca(history)
        self.assertFalse(is_valid)
        self.assertIn("Validation Failed", err)

    def test_rca_schema_validation_missing_supporting_evidence(self):
        """Verifies that a claim missing supporting evidence fails validation."""
        invalid_rca = {
            "summary": "Summary",
            "root_cause": "Cause",
            "confidence": "High",
            "claims": [{"claim": "No evidence provided"}], # Missing supporting_evidence
            "unknowns": [],
            "assessment": "None"
        }
        
        invalid_tool_call = {
            "function": {
                "name": "dfir__update_case_notes__v1",
                "arguments": json.dumps({"notes": f"```json\n{json.dumps(invalid_rca)}\n```"})
            }
        }
        
        history = [{"role": "assistant", "tool_calls": [invalid_tool_call]}]
        is_valid, err = orch.check_for_rca(history)
        self.assertFalse(is_valid)
        self.assertIn("'supporting_evidence' is a required property", err)

    def test_prompt_integrity(self):
        """Verifies that the system prompt contains Phase 13 expert directives."""
        # We simulate the prompt generation or check file content
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("INFERENCE POLICY", content)
            self.assertIn("SEPARATION OF CONCERNS", content)
            self.assertIn("PROVENANCE REQUIREMENT", content)
            self.assertIn("root_cause.schema.json", content)

if __name__ == "__main__":
    unittest.main()
