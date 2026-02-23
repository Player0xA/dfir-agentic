import os
import json
import time
import unittest
from unittest.mock import patch
import tools.orchestrator.deepseek_orchestrator as orch

class TestV7ParallelOrdering(unittest.TestCase):
    def setUp(self):
        os.environ["DEEPSEEK_API_KEY"] = "fake-key"
        self.intake_path = "/tmp/v7_intake.json"
        with open(self.intake_path, "w") as f:
            json.dump({"intake_id": "V7-TEST"}, f)
            
        # Mocking intake directory contents
        self.case_dir = "/tmp"

    @patch('tools.orchestrator.deepseek_orchestrator.deepseek_chat')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_tools_call')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_read_json')
    def test_parallel_execution_ordering(self, mock_read_json, mock_mcp, mock_chat):
        # Scenario: AI calls two tools simultaneously
        mock_read_json.return_value = {"value": {"intake_id": "V7-TEST"}}
        
        # Mock 2 tool calls in one response
        mock_chat.return_value = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Running two things.",
                    "tool_calls": [
                        {"id": "call_SLOW", "function": {"name": "dfir__read_text__v1", "arguments": json.dumps({"path": "/tmp/t1.txt"})}},
                        {"id": "call_FAST", "function": {"name": "dfir__read_text__v1", "arguments": json.dumps({"path": "/tmp/t2.txt"})}}
                    ]
                }
            }]
        }
        
        # We want the FIRST call ("call_SLOW") to take longer than the SECOND call ("call_FAST").
        # If we were using as_completed, "call_FAST" would append first.
        # With mapped list, "call_SLOW" should append first.
        def mock_mcp_call(name, args):
            if args["path"] == "/tmp/t1.txt":
                time.sleep(0.5)
                return {"val": "SLOW"}
            else:
                time.sleep(0.1)
                return {"val": "FAST"}
                
        mock_mcp.side_effect = mock_mcp_call

        import sys
        
        with patch.object(sys, 'argv', ["prog", "--intake-json", self.intake_path, "--mode", "autonomous"]):
            with patch('tools.orchestrator.deepseek_orchestrator.check_for_rca', return_value=True):
                # We need to capture the history.
                mock_chat.side_effect = [
                    mock_chat.return_value,
                    {"choices": [{"message": {"role": "assistant", "content": "Done <promise>TASK_COMPLETE</promise>"}}]}
                ]
                
                orch.main()
            
        # Inspect history from response.json
        import glob
        import shutil
        
        resp_files = glob.glob("/tmp/orchestrator/*/response.json")
        resp_files.sort(key=os.path.getmtime)
        self.assertTrue(len(resp_files) > 0, "response.json not found")
        
        with open(resp_files[-1], "r") as f:
            history = json.load(f)
            
        # History format: system, user, assistant(with tools), tool_result1, tool_result2, assistant(done)
        tool_results = [m for m in history if m["role"] == "tool"]
        
        # Allow cleanup of glob
        import shutil
        out_dir = os.path.dirname(resp_files[-1])
        shutil.rmtree(out_dir)
        
        self.assertEqual(len(tool_results), 2, "Should have 2 tool results appended.")
        
        # VERIFY ORDERING
        self.assertEqual(tool_results[0]["tool_call_id"], "call_SLOW")
        self.assertEqual(tool_results[1]["tool_call_id"], "call_FAST")
        
        print("[SUCCESS] Parallel Ordering Verified: Results appended in requested sequence, defying thread completion time.")

if __name__ == "__main__":
    unittest.main()
