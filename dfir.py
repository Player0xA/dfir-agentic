#!/usr/bin/env python3
import sys
import argparse
import subprocess
import re
from pathlib import Path
import sys, os
print("MCP SERVER sys.executable =", sys.executable)
print("MCP SERVER VIRTUAL_ENV    =", os.environ.get("VIRTUAL_ENV"))

def run_cmd(cmd: list[str], task_name: str):
    print(f"\n>>> [Stage: {task_name}] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"FAILED: {task_name}\nERROR: {result.stderr}", file=sys.stderr)
        return None
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Agentic DFIR Unified CLI")
    parser.add_argument("evidence_path", nargs="?", help="Path to raw evidence (file/dir) or case.json")
    parser.add_argument("--mode", choices=["structured", "autonomous"], default="structured")
    parser.add_argument("--auto", action="store_true", help="Shorthand for --mode autonomous")
    parser.add_argument("--task", help="Optional mission objective")
    args = parser.parse_args()

    # 0. RESOLVE CASE/INTAKE
    effective_mode = "autonomous" if args.auto else args.mode
    case_dir = os.environ.get("DFIR_CASE_DIR")
    intake_path = None

    target = args.evidence_path
    if not target and case_dir:
        # Check for case.json in DFIR_CASE_DIR
        candidate = Path(case_dir) / "case.json"
        if candidate.exists():
            target = str(candidate)

    if not target:
        parser.print_help()
        print("\nERROR: No evidence path provided and DFIR_CASE_DIR not set/invalid.", file=sys.stderr)
        sys.exit(1)

    target_path = Path(target)
    
    # Check if we can skip Onboarding (Stage 1)
    if target_path.suffix == ".json" and target_path.name in ["case.json", "intake.json"]:
        intake_path = str(target_path.resolve())
        print(f"[+] Using existing case metadata: {intake_path}")
    else:
        # 1. IDENTIFY (Onboarding)
        identify_cmd = [
            "python3", "tools/intake/identify_evidence.py", 
            str(target_path), 
            "--out-base", "outputs/intake"
        ]
        out = run_cmd(identify_cmd, "Onboarding")
        if not out: sys.exit(1)
        
        match = re.search(r"OK: wrote (.+)", out)
        if not match:
            print(f"FAILED: Could not parse intake.json path from output: {out}", file=sys.stderr)
            sys.exit(1)
        intake_path = match.group(1).strip()
        # Update context for sub-processes
        new_case_dir = str(Path(intake_path).parent.resolve())
        os.environ["DFIR_CASE_DIR"] = new_case_dir
        print(f"[+] Identified Case: {intake_path}")
        print(f"[+] Effective DFIR_CASE_DIR: {new_case_dir}")

    # 2. INGEST (Deterministic Ingestion)
    # Skip if it's already a case.json (which implies ingestion/staging might be handled externally)
    # but for compatibility, we'll let auto_run attempt its logic if needed.
    ingest_cmd = [
        "python3", "tools/router/auto_run.py",
        "--intake-json", intake_path,
        "--enrichment-policy", "always",
        "--run-merge"
    ]
    if args.task:
        ingest_cmd.extend(["--task", args.task])
    if run_cmd(ingest_cmd, "Deterministic Ingestion") is None: sys.exit(1)

    # 3. ORCHESTRATE (Agentic Loop)
    orchestrate_cmd = [
        "python3", "tools/orchestrator/deepseek_orchestrator.py",
        "--intake-json", intake_path,
        "--mode", effective_mode
    ]
    if args.task:
        orchestrate_cmd.extend(["--task", args.task])

    # For the orchestrator, we don't want to capture output because of interactive prompts
    print(f"\n>>> [Stage: Agentic Loop] Running: {' '.join(orchestrate_cmd)}")
    subprocess.run(orchestrate_cmd)

if __name__ == "__main__":
    main()
