import os
import json
import unittest
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch

class TestPhase14Hardening(unittest.TestCase):
    def test_first_action_mandate(self):
        """Verify that First-Action mandate requires evidence fetch."""
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("First-Action Mandate", content)
            self.assertIn("batch_has_evidence", content)
            self.assertIn("iteration in [1, 2]", content)

    def test_budget_constraints(self):
        """Verify that tool costs and budgets are enforced."""
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("budget_points = 15", content)
            self.assertIn("budget_points - cost < 0", content)
            self.assertIn("TOOL_COSTS =", content)

    def test_jsonl_structured_logging(self):
        """Verify that JSONL structured logging code was added."""
        with open("tools/orchestrator/deepseek_orchestrator.py", "r") as f:
            content = f.read()
            self.assertIn("progress.jsonl", content)
            self.assertIn("JSONL Structured Progress Logging", content)

    def test_new_mcp_tools(self):
        """Verify the new tools exist in the MCP server."""
        with open("tools/mcp/dfir_mcp_server.py", "r") as f:
            content = f.read()
            self.assertIn("dfir.build_query_plan@1", content)
            self.assertIn("dfir.validate_deliverable@1", content)
            self.assertIn("dfir.load_case_context@1", content)
            self.assertIn("auto_pivot_extraction", content)

if __name__ == "__main__":
    unittest.main()
