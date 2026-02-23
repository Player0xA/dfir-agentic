import os
import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

from tools.orchestrator.deepseek_orchestrator import mcp_tools_call, _get_skills_registry

def test_load_skill():
    print("=== Testing dfir.load_skill@1 ===")
    
    # 1. Test loading SKILL.md (should strip YAML)
    print("[*] Loading analyzing-timeline/SKILL.md...")
    res = mcp_tools_call("dfir.load_skill@1", {"skill_name": "analyzing-timeline"})
    content = res["result"]["content"]
    
    if "name: analyzing-timeline" in content:
        print("FAILED: YAML frontmatter was NOT stripped.")
    elif "# Timeline Analysis Instructions" in content:
        print("SUCCESS: Loaded SKILL.md and stripped YAML.")
    else:
        print(f"FAILED: Unexpected content: {content[:100]}...")

    # 2. Test loading specific file
    print("[*] Loading analyzing-timeline/psort_cheatsheet.md...")
    res = mcp_tools_call("dfir.load_skill@1", {"skill_name": "analyzing-timeline", "file_name": "psort_cheatsheet.md"})
    content = res["result"]["content"]
    
    if "# Plaso psort Cheatsheet" in content:
        print("SUCCESS: Loaded psort_cheatsheet.md correctly.")
    else:
        print(f"FAILED: Unexpected content: {content[:100]}...")

def test_registry_injection():
    print("\n=== Testing Skills Registry Injection ===")
    registry = _get_skills_registry()
    print("[*] Generated Skills Registry:")
    print("-" * 30)
    print(registry)
    print("-" * 30)
    
    if "- analyzing-timeline: Use this skill" in registry and "- parsing-registry: Use this skill" in registry:
        print("SUCCESS: Skills Registry contains both skills with descriptions.")
    else:
        print("FAILED: Skills Registry is incomplete or malformed.")

if __name__ == "__main__":
    test_load_skill()
    test_registry_injection()
