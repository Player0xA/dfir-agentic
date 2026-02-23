import os
import json
import uuid
from pathlib import Path

# Mock DeepSeek API response for the "Sabotage Test"
# Iteration 1: Calls a non-existent tool 'dfir.non_existent_tool'
# Iteration 2: Corrects itself and calls 'dfir.load_skill@1'
# Iteration 3: Updates case notes and finishes

MOCK_RESPONSES = [
    {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "I will start by calling a tool that doesn't exist.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "dfir.non_existent_tool",
                        "arguments": "{}"
                    }
                }]
            }
        }]
    },
    {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Ah, it seems that tool failed. Let me load the timeline skill instead.",
                "tool_calls": [{
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "dfir.load_skill@1",
                        "arguments": "{\"skill_name\": \"analyzing-timeline\"}"
                    }
                }]
            }
        }]
    },
    {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Skill loaded. Now saving progress and finishing.\n<promise>TASK_COMPLETE</promise>",
                "tool_calls": [{
                    "id": "call_3",
                    "type": "function",
                    "function": {
                        "name": "dfir.update_case_notes@1",
                        "arguments": "{\"notes\": \"Loaded timeline skill. Next Steps: Start querying Plaso.\"}"
                    }
                }]
            }
        }]
    }
]

def simulate_sabotage_loop():
    print("=== Phase 4: The Sabotage Test ===")
    
    # We will monkeypatch deepseek_chat to return our mock responses
    import tools.orchestrator.deepseek_orchestrator as orch
    
    mock_idx = 0
    def mock_chat(messages, **kwargs):
        nonlocal mock_idx
        res = MOCK_RESPONSES[mock_idx]
        mock_idx += 1
        return res
    
    orch.deepseek_chat = mock_chat
    
    # Set dummy env vars
    os.environ["DEEPSEEK_API_KEY"] = "fake-key"
    
    # Run a simplified version of main or just trigger the logic
    # To keep it clean, we'll assume the refactor is working if the loop handles mock_idx
    
    # We need a fake intake.json
    intake_dir = "/tmp/sabotage_test"
    os.makedirs(intake_dir, exist_ok=True)
    intake_path = os.path.join(intake_dir, "intake.json")
    with open(intake_path, "w") as f:
        json.dump({"intake_id": "TEST-404"}, f)
    
    # Setup args
    import argparse
    from unittest.mock import MagicMock
    args = MagicMock()
    args.intake_json = intake_path
    
    # Execute (this will trigger the actual loop in deepseek_orchestrator.py)
    # We'll use a sys.exit(0) catch or just run the function
    print("[*] Starting Orchestrator Loop Simulation...")
    try:
        # We need to mock mcp_tools_call too to avoid actual subprocess calls 
        # unless we want to test the full stack (but we want to test the LOOP first)
        original_mcp_call = orch.mcp_tools_call
        
        def mock_mcp_call(name, args):
            if name == "dfir.non_existent_tool":
                raise KeyError(f"unknown tool: {name}")
            if name == "dfir.read_json@1":
                # Simulated file content
                return {"value": {"intake_id": "TEST-404"}}
            return {"status": "success", "tool": name}
            
        orch.mcp_tools_call = mock_mcp_call
        
        # Patch argparse
        import sys
        sys.argv = ["prog", "--intake-json", intake_path]
        
        orch.main()
        
    except SystemExit as e:
        if e.code == 0:
            print("\n[SUCCESS] Loop finished with code 0.")
        else:
            print(f"\n[FAILED] Loop exited with code {e.code}")
    except Exception as e:
        print(f"\n[ERROR] Simulation crashed: {e}")

if __name__ == "__main__":
    simulate_sabotage_loop()
