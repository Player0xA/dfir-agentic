import os
import json
import unittest
from unittest.mock import patch, MagicMock
import tools.orchestrator.deepseek_orchestrator as orch

class TestDualModeOrchestrator(unittest.TestCase):
    def setUp(self):
        # Fake environment
        os.environ["DEEPSEEK_API_KEY"] = "fake-key"
        self.intake_path = "/tmp/test_intake.json"
        with open(self.intake_path, "w") as f:
            json.dump({"intake_id": "TEST-MODE"}, f)

    @patch('tools.orchestrator.deepseek_orchestrator.deepseek_chat')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_tools_call')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_read_json')
    @patch('tools.orchestrator.deepseek_orchestrator.input')
    def test_structured_mode_approve(self, mock_input, mock_read_json, mock_mcp, mock_chat):
        # Scenario: AI proposes a tool, human approves
        mock_input.return_value = 'y'
        mock_read_json.return_value = {"value": {"intake_id": "TEST-INTAKE"}}
        mock_mcp.return_value = {"status": "success"}
        
        # Iteration 1: Propose tool
        # Iteration 2: TASK_COMPLETE
        mock_chat.side_effect = [
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Proposing auto_run.",
                        "tool_calls": [{"id": "c1", "function": {"name": "dfir__auto_run__v1", "arguments": "{}"}}]
                    }
                }]
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "<promise>TASK_COMPLETE</promise>"
                    }
                }]
            }
        ]

        # Patch sys.argv for structured mode
        import sys
        with patch.object(sys, 'argv', ["prog", "--intake-json", self.intake_path, "--mode", "structured"]):
            res = orch.main()
            self.assertEqual(res, 0)
        
        mock_mcp.assert_called_with("dfir.auto_run@1", {})
        print("[SUCCESS] Structured Mode: Human Approval verified.")

    @patch('tools.orchestrator.deepseek_orchestrator.deepseek_chat')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_tools_call')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_read_json')
    @patch('tools.orchestrator.deepseek_orchestrator.input')
    def test_structured_mode_modify(self, mock_input, mock_read_json, mock_mcp, mock_chat):
        # Scenario: AI proposes bad tool, human modifies
        # Input 1: 'modify'
        # Input 2: 'Correction text'
        mock_input.side_effect = ['modify', 'Use load_skill instead']
        mock_read_json.return_value = {"value": {"intake_id": "TEST-INTAKE"}}
        
        mock_chat.side_effect = [
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Proposing bad_tool.",
                        "tool_calls": [{"id": "c1", "function": {"name": "bad_tool", "arguments": "{}"}}]
                    }
                }]
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "<promise>TASK_COMPLETE</promise>"
                    }
                }]
            }
        ]

        import sys
        with patch.object(sys, 'argv', ["prog", "--intake-json", self.intake_path, "--mode", "structured"]):
            res = orch.main()
            self.assertEqual(res, 0)
        
        # Verify mcp_tools_call was NOT called for bad_tool
        self.assertFalse(any(call.args[0] == "bad_tool" for call in mock_mcp.call_args_list))
        print("[SUCCESS] Structured Mode: Human Modification verified.")

    @patch('tools.orchestrator.deepseek_orchestrator.deepseek_chat')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_tools_call')
    @patch('tools.orchestrator.deepseek_orchestrator.mcp_read_json')
    @patch('tools.orchestrator.deepseek_orchestrator.input')
    def test_autonomous_mode(self, mock_input, mock_read_json, mock_mcp, mock_chat):
        # Scenario: Autonomous mode should NOT call input()
        mock_read_json.return_value = {"value": {"intake_id": "TEST-INTAKE"}}
        mock_mcp.return_value = {"status": "success"}
        mock_chat.side_effect = [
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Running auto_run autonomously.",
                        "tool_calls": [{"id": "c1", "function": {"name": "dfir__auto_run__v1", "arguments": "{}"}}]
                    }
                }]
            },
            {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "<promise>TASK_COMPLETE</promise>"
                    }
                }]
            }
        ]

        import sys
        with patch.object(sys, 'argv', ["prog", "--intake-json", self.intake_path, "--mode", "autonomous"]):
            res = orch.main()
            self.assertEqual(res, 0)
        
        mock_input.assert_not_called()
        self.assertTrue(any(call.args[0] == "dfir.auto_run@1" for call in mock_mcp.call_args_list))
        print("[SUCCESS] Autonomous Mode: No Human Input required verified.")

    @patch('tools.orchestrator.deepseek_orchestrator.mcp_tools_call')
    def test_query_findings_logic(self, mock_mcp):
        # Scenario: Verify the MCP tool logic for query_findings (internal test)
        from tools.mcp.dfir_mcp_server import tool_query_findings
        
        # Create a mock findings file
        findings_doc = {
            "findings": [
                {"finding_id": "f1", "finding": {"severity": "critical", "mitre_tags": ["T1547"]}},
                {"finding_id": "f2", "finding": {"severity": "high", "mitre_tags": ["T1059"]}},
                {"finding_id": "f3", "finding": {"severity": "critical", "mitre_tags": ["T1003"]}}
            ]
        }
        f_path = "/tmp/test_findings.json"
        with open(f_path, "w") as f:
            json.dump(findings_doc, f)
            
        # Test Severity Filter
        res = tool_query_findings({"path": f_path, "severity": "critical"}, {})
        self.assertEqual(len(res["results"]), 2)
        print("[SUCCESS] Query Tool: Severity Filter verified.")
        
        # Test ID Filter
        res = tool_query_findings({"path": f_path, "finding_id": "f2"}, {})
        self.assertEqual(len(res["results"]), 1)
        self.assertEqual(res["results"][0]["finding_id"], "f2")
        print("[SUCCESS] Query Tool: ID Filter verified.")

        # Test Tactic Filter
        res = tool_query_findings({"path": f_path, "mitre_tactic": "T1547"}, {})
        self.assertEqual(len(res["results"]), 1)
        print("[SUCCESS] Query Tool: Tactic Filter verified.")

if __name__ == "__main__":
    unittest.main()
