#!/usr/bin/env python3
"""
verify_v52_tool_exposure.py

Verification script for Phase 51/52 to ensure that the AI Agent is given the correct set of MCP tools depending on the classification of the evidence (Disk Image vs. Memory Dump).

Run this on your testing host!
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.orchestrator.deepseek_orchestrator import mcp_list_tools

def print_tools(scenario_name: str, tools: list[dict]):
    print(f"\n{'='*60}")
    print(f"[{scenario_name}] - Total Tools Loaded: {len(tools)}")
    print(f"{'='*60}")
    
    # Group by prefix
    dfir_tools = [t for t in tools if t['name'].startswith('dfir.')]
    mem_tools = [t for t in tools if t['name'].startswith('memory_') or t['name'].startswith('vt_')]
    win_tools = [t for t in tools if not t['name'].startswith('dfir.') and not t['name'].startswith('memory_') and not t['name'].startswith('vt_')]
    
    print(f"\n> Base DFIR Tools ({len(dfir_tools)}):")
    for t in dfir_tools:
        print(f"  - {t['name']}")
        
    print(f"\n> Memory Forensics Tools ({len(mem_tools)}):")
    if mem_tools:
        for t in mem_tools:
            print(f"  - {t['name']}")
    else:
        print("  (None loaded - restricted)")
        
    print(f"\n> Windows Forensics Tools ({len(win_tools)}):")
    if win_tools:
        for t in win_tools:
            print(f"  - {t['name']}")
    else:
        print("  (None loaded - restricted)")

def main():
    print("Initializing MCP Client Discovery...")
    
    # 1. Base tools (always loaded)
    base_tools = mcp_list_tools("dfir")
    
    # 2. Simulate Memory Dump Case
    print("\n--- Simulating MEMORY DUMP Case ---")
    memory_context_tools = list(base_tools)
    try:
        mem_additions = mcp_list_tools("mem")
        memory_context_tools.extend(mem_additions)
    except Exception as e:
        print(f"[!] Errored loading mem tools: {e}")
        
    print_tools("SCENARIO A: Memory Dump (e.g., .raw, .vmem)", memory_context_tools)
    
    # 3. Simulate Disk Image Case
    print("\n\n--- Simulating DISK IMAGE Case ---")
    disk_context_tools = list(base_tools)
    try:
        win_additions = mcp_list_tools("win")
        disk_context_tools.extend(win_additions)
    except Exception as e:
        print(f"[!] Errored loading win tools: {e}")
        
    print_tools("SCENARIO B: Windows Disk Image (e.g., .dd, .e01)", disk_context_tools)
    print("\nVerification Complete.")

if __name__ == "__main__":
    main()
