#!/usr/bin/env python3
import sys
import argparse
import subprocess
import re
from pathlib import Path

def run_cmd(cmd: list[str], task_name: str):
    print(f"\n>>> [Stage: {task_name}] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"FAILED: {task_name}\nERROR: {result.stderr}", file=sys.stderr)
        return None
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Agentic DFIR Unified CLI")
    parser.add_argument("evidence_path", help="Path to raw evidence (file or dir)")
    parser.add_argument("--mode", choices=["structured", "autonomous"], default="structured")
    parser.add_argument("--task", help="Optional mission objective")
    args = parser.parse_args()

    # 1. IDENTIFY (Onboarding)
    identify_cmd = [
        "python3", "tools/intake/identify_evidence.py", 
        args.evidence_path, 
        "--out-base", "outputs/intake"
    ]
    out = run_cmd(identify_cmd, "Onboarding")
    if not out: sys.exit(1)
    
    # Extract path: "OK: wrote outputs/intake/uuid/intake.json"
    match = re.search(r"OK: wrote (.+)", out)
    if not match:
        print(f"FAILED: Could not parse intake.json path from output: {out}", file=sys.stderr)
        sys.exit(1)
    intake_path = match.group(1).strip()
    print(f"[+] Identified Case: {intake_path}")

    # 2. INGEST (Deterministic Ingestion)
    ingest_cmd = [
        "python3", "tools/router/auto_run.py",
        "--intake-json", intake_path,
        "--enrichment-policy", "always",
        "--run-merge"
    ]
    if run_cmd(ingest_cmd, "Deteministic Ingestion") is None: sys.exit(1)

    # 3. ORCHESTRATE (Agentic Loop)
    orchestrate_cmd = [
        "python3", "tools/orchestrator/deepseek_orchestrator.py",
        "--intake-json", intake_path,
        "--mode", args.mode
    ]
    if args.task:
        orchestrate_cmd.extend(["--task", args.task])

    # For the orchestrator, we don't want to capture output because of interactive prompts
    print(f"\n>>> [Stage: Agentic Loop] Running: {' '.join(orchestrate_cmd)}")
    subprocess.run(orchestrate_cmd)

if __name__ == "__main__":
    main()
