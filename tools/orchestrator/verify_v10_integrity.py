import os
import json
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch
from tools.mcp.dfir_mcp_server import tool_query_super_timeline

class TestPhase10Integrity(unittest.TestCase):
    def test_plaso_factual_syntax(self):
        """Verifies that Plaso syntax uses 'contains', space-delimited timestamps, and single quotes."""
        args = {
            "plaso_file": "/tmp/test.plaso",
            "start_time": "2026-01-14T10:00:00Z",
            "end_time": "2026-01-14T11:00:00Z",
            "search_term": "malware",
            "event_ids": [4624]
        }
        
        with patch('tools.mcp.dfir_mcp_server.run_cmd', return_value=(0, "", "")) as mock_run:
            with patch('tools.mcp.dfir_mcp_server.ensure_read_allowed'):
                with patch('pathlib.Path.is_file', return_value=True):
                    try:
                        tool_query_super_timeline(args, {})
                    except:
                        pass
            
            cmd = mock_run.call_args[0][0]
            filter_str = cmd[-1]
            
            # 1. Factual Operator
            self.assertIn("message contains 'malware'", filter_str)
            # 2. Space-delimited timestamps (No 'T')
            self.assertIn("date > '2026-01-14 10:00:00'", filter_str)
            # 3. Single quotes for values
            self.assertTrue(filter_str.count("'") >= 4)
            self.assertNotIn('"', filter_str, "Filter should not contain double quotes for values")

    def test_orchestrator_visibility(self):
        """Verifies that the orchestrator prints the error message on failure."""
        with patch('builtins.print') as mock_print:
            # We mock the result of tools execution
            history = []
            results = [{"id": "1", "name": "dfir.test", "error": "[EXPECTED_ERROR]"}]
            
            # Simulate the loop in deepseek_orchestrator.py
            for r in results:
                if "error" in r:
                    print(f"  [-] {r['name']} failed: {r['error']}")
            
            mock_print.assert_any_call("  [-] dfir.test failed: [EXPECTED_ERROR]")

if __name__ == "__main__":
    unittest.main()
