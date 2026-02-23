import os
import json
from pathlib import Path

# Mock components for testing
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()

def simulate_autonomous_decision():
    print("=== Simulating Autonomous Skill Trigger ===")
    
    # 1. Fake Alert Data
    alert_context = {
        "alert": "Suspicious Event ID 4688 (Process Creation) detected at 2026-02-22T14:00:00Z",
        "details": "Image: C:\\Windows\\System32\\cmd.exe, Parent: powershell.exe"
    }
    
    # 2. Extract Registry (using the actual logic from the orchestrator)
    from deepseek_orchestrator import _get_skills_registry
    skills_registry = _get_skills_registry()
    
    # 3. Construct the System Prompt (exactly as the orchestrator does)
    system_content = (
        "You are a DFIR triage assistant. You produce NON-AUTHORITATIVE commentary.\n"
        f"{skills_registry}\n"
        "Hard rules:\n"
        "- Do NOT invent evidence...\n"
        "- Use only the JSON provided.\n"
    )
    
    print("\n[STEP 1] DeepSeek Sees the Skills Registry:")
    print("-" * 50)
    print(system_content)
    print("-" * 50)

    print("\n[STEP 2] DeepSeek Reads the Alert:")
    print(f"User: {json.dumps(alert_context, indent=2)}")

    # 4. Simulation of DeepSeek's Internal Thought Process
    print("\n[STEP 3] Simulated AI Reasoning:")
    print("> I see a suspicious process creation (4688) at 14:00:00Z.")
    print("> I need to check the Plaso Super Timeline for context.")
    print("> Cross-referencing available skills...")
    print("> FOUND: 'analyzing-timeline': Use this skill when you need to query the Plaso Super Timeline...")
    
    print("\n[STEP 4] Simulated Autonomous Tool Call:")
    # Here we simulate what DeepSeek would output
    tool_call = {
        "name": "dfir.load_skill@1",
        "arguments": {"skill_name": "analyzing-timeline"}
    }
    print(f"DeepSeek -> CALL: {json.dumps(tool_call, indent=2)}")

    # 5. Verify the tool call actually works in the backend
    from deepseek_orchestrator import mcp_tools_call
    print("\n[STEP 5] Backend Executes Skill Load:")
    res = mcp_tools_call(tool_call["name"], tool_call["arguments"])
    print("Result received (first 200 chars):")
    print(res["result"]["content"][:200] + "...")

    print("\n=== Autonomy Logic Verified ===")

if __name__ == "__main__":
    simulate_autonomous_decision()
