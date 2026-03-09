#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic agent selection (HTM v0.1)")
    ap.add_argument("--intake-json", required=True, help="path to intake.json")
    ap.add_argument("--registry", default=".agents/registry.json", help="agent registry json")
    ap.add_argument("--task", help="Investigative intent/task description")
    args = ap.parse_args()

    intake_path = Path(args.intake_json)
    reg_path = Path(args.registry)

    if not intake_path.is_file():
        print(f"FAIL: intake not found: {intake_path}", file=sys.stderr)
        return 2
    if not reg_path.is_file():
        print(f"FAIL: registry not found: {reg_path}", file=sys.stderr)
        return 2

    intake = load_json(intake_path)
    
    # Schema Detection (V30 Compatibility)
    if "case_id" in intake:
        # It's a case.json
        intake_id = intake["case_id"]
        # Inferred classification based on evidence
        evidence_types = [e["type"] for e in intake.get("evidence", [])]
        if "windows_triage_dir" in evidence_types:
            kind = "windows_triage_dir"
        elif "evtx" in evidence_types or "evtx_dir" in evidence_types:
            kind = "windows_evtx_dir"
        else:
            kind = "generic"
    else:
        # Legacy intake.json
        intake_id = intake["intake_id"]
        kind = intake["classification"]["kind"]

    # deterministic mapping
    if kind in ("windows_evtx_dir", "windows_evtx_file", "windows_triage_dir"):
        agent_id = "windows_evtx_agent"
    else:
        agent_id = "triage_agent"

    # Playbook Selection (V37)
    playbook = "initial_access_v1"
    if kind == "windows_triage_dir":
        playbook = "windows_triage_v1"
        
    if args.task:
        task_lower = args.task.lower()
        if any(k in task_lower for k in ["tamper", "clear", "audit"]):
            playbook = "log_tampering_v1"
        elif any(k in task_lower for k in ["lateral", "remote", "pivot", "move", "rdp", "smb"]):
            playbook = "lateral_movement_v1"
        elif any(k in task_lower for k in ["persistence", "service", "start", "run", "task"]):
            playbook = "persistence_v1"

    out = {
        "intake_id": intake_id,
        "kind": kind,
        "selected_agent": agent_id,
        "selected_playbook": playbook
    }
    print(json.dumps(out, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

