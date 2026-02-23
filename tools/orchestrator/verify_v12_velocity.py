import os
import json
import unittest
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch

class TestPhase12Velocity(unittest.TestCase):
    def test_ninth_inning_warning(self):
        """Verifies the 9th inning system warning is injected at iteration 8 and 9."""
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("iteration in [8, 9]", content)
            self.assertIn("[System WARNING]: You only have", content)
            self.assertIn("10-STEP DOOM CLOCK", content)
            self.assertIn("MANDATED TOOL CHAINING", content)
            self.assertIn("PIVOT EXTRACTION", content)

    def test_convergence_guard(self):
        """Verifies that completion is rejected if RCA is missing."""
        history_missing = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "I am done. <promise>TASK_COMPLETE</promise>"}
        ]
        
        # Valid RCA requires an update_case_notes tool call containing the RCA block
        valid_tool_call = {
            "function": {
                "name": "dfir__update_case_notes__v1",
                "arguments": "{\"notes\": \"Here is the root_cause_analysis.json findings...\"}"
            }
        }
        
        history_present = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "Writing notes...", "tool_calls": [valid_tool_call]},
            {"role": "assistant", "content": "I am done. <promise>TASK_COMPLETE</promise>"}
        ]
        
        self.assertFalse(orch.check_for_rca(history_missing))
        self.assertTrue(orch.check_for_rca(history_present))
        
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("[System Error]: Cannot complete task. 'root_cause_analysis.json' is missing from your case notes.", content)

if __name__ == "__main__":
    unittest.main()
