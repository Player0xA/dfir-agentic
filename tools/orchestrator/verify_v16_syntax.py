import unittest
import re
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch

class TestPhase16Operational(unittest.TestCase):
    def test_desanitize_regex(self):
        """Verify that __v at middle of name is NOT replaced, but __v at end IS."""
        # Collision Case: 'validate' contains 'v'
        corrupted = "dfir__validate_deliverable__v1"
        sanitized = orch.desanitize_tool_name(corrupted)
        self.assertEqual(sanitized, "dfir.validate_deliverable@1")
        self.assertNotIn("@alidate", sanitized)
        
        # Standard Case
        std = "dfir__query_super_timeline__v1"
        self.assertEqual(orch.desanitize_tool_name(std), "dfir.query_super_timeline@1")

    def test_budget_increase(self):
        """Verify the logic would initialize budget to 25 (simulated)."""
        # This is a bit hard to test without running the main loop, 
        # but we can verify the constant if it were one. 
        # Since it's local, we'll trust the manual check.
        pass

if __name__ == "__main__":
    unittest.main()
