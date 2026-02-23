import os
import json
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tools.orchestrator.deepseek_orchestrator as orch
from tools.mcp.dfir_mcp_server import tool_query_super_timeline

class TestPhase8Upgrades(unittest.TestCase):
    def setUp(self):
        self.intake_dir = "/Users/marianosanchezrojas/dfir-agentic/dfir-agentic/outputs/v8_test_case"
        os.makedirs(self.intake_dir, exist_ok=True)
        self.intake_path = os.path.join(self.intake_dir, "intake.json")
        with open(self.intake_path, "w") as f:
            json.dump({"intake_id": "V8-TEST"}, f)
        
        # Create a dummy case_summary.md
        with open(os.path.join(self.intake_dir, "case_summary.md"), "w") as f:
            f.write("# Summary\nArtifacts identified.")
        
        os.environ["DEEPSEEK_API_KEY"] = "fake-key"

    def test_claude_md_generation(self):
        # Trigger the discovery logic manually or via main patch
        with patch('tools.orchestrator.deepseek_orchestrator.mcp_read_json', return_value={"value": {"intake_id": "V8-TEST"}}):
            with patch('tools.orchestrator.deepseek_orchestrator.deepseek_chat', return_value={"choices": [{"message": {"role": "assistant", "content": "<promise>TASK_COMPLETE</promise>"}}]}):
                import sys
                with patch.object(sys, 'argv', ["prog", "--intake-json", self.intake_path, "--mode", "autonomous"]):
                    with patch('tools.orchestrator.deepseek_orchestrator.check_for_rca', return_value=True):
                        orch.main()
        
        claude_path = os.path.join(self.intake_dir, "CLAUDE.md")
        self.assertTrue(os.path.exists(claude_path), "CLAUDE.md should be generated in intake dir")
        with open(claude_path, "r") as f:
            content = f.read()
            self.assertIn("Forensic Project Memory", content)
            self.assertIn("Case Envelope", content)
            self.assertIn("case_summary.md", content)

    def test_plaso_backend_abstraction(self):
        # Test the mcp tool directly for syntax construction
        args = {
            "plaso_file": "/tmp/test.plaso",
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T01:00:00Z",
            "search_term": "evil.exe",
            "event_ids": [4624, 1102]
        }
        
        with patch('tools.mcp.dfir_mcp_server.run_cmd', return_value=(0, "", "")) as mock_run:
            with patch('tools.mcp.dfir_mcp_server.ensure_read_allowed'):
                with patch('pathlib.Path.is_file', return_value=True):
                    try:
                        tool_query_super_timeline(args, {})
                    except:
                        pass # Expecting fail on file read, but we check the command
            
            cmd = mock_run.call_args[0][0]
            # Check the constructed filter string
            filter_str = cmd[-1]
            self.assertIn('message contains "evil.exe"', filter_str)
            self.assertIn('event_identifier IN (4624,1102)', filter_str)
            self.assertIn('date > "2026-01-01T00:00:00Z"', filter_str)

if __name__ == "__main__":
    unittest.main()
