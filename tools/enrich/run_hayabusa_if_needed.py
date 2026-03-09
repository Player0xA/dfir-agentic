#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

REGISTRY = Path(".agents/registry.json")
ENFORCE = Path("tools/router/enforce_capabilities.py")
HAYABUSA_PIPELINE = Path("pipelines/hayabusa_evtx/run.sh")

PLAN_SCHEMA = Path("contracts/enrichment.plan.schema.json")
PLAN_VALIDATOR = Path("tools/contracts/validate_enrichment_plan.py")

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def run_capture(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def run_must(cmd):
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)

def must_file(p: Path, label: str) -> None:
    if not p.is_file():
        raise SystemExit(f"FAIL: {label} not found: {p}")

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic enrichment runner (executes an enrichment_plan.json)")
    ap.add_argument("--plan-json", required=True, help="path to enrichment_plan.json")
    ap.add_argument("--out-json", required=True, help="path to write enrichment.json (result)")
    args = ap.parse_args()

    plan_path = Path(args.plan_json)
    must_file(plan_path, "enrichment_plan.json")

    # Validate plan schema
    must_file(PLAN_SCHEMA, "plan schema")
    must_file(PLAN_VALIDATOR, "plan validator")
    run_must([str(PLAN_VALIDATOR), str(PLAN_SCHEMA), str(plan_path)])

    plan = load_json(plan_path)
    agent_id = plan["agent_id"]
    enrichment_id = plan["enrichment"]["enrichment_id"]

    out_doc = {
        "timestamp_utc": utc_now_z(),
        "plan_json": str(plan_path),
        "agent_id": agent_id,
        "baseline": {
            "auto_json": plan["baseline"]["auto_json"],
            "baseline_manifest_path": plan["baseline"]["baseline_manifest_path"],
            "evtx_dir": plan["baseline"]["evtx_dir"]
        },
        "decision": plan["decision"],
        "enforcement": None,
        "result": {"status": "skipped", "run_id": None, "manifest_path": None}
    }

    if not plan["decision"]["should_run"]:
        out_doc["result"]["status"] = "skipped"
        Path(args.out_json).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
        print(f"OK: wrote {args.out_json}")
        return 0

    # Enforce run_enrichment capability
    code, out, err = run_capture([
        str(ENFORCE),
        "--registry", str(REGISTRY),
        "--agent-id", agent_id,
        "--action", "run_enrichment",
        "--enrichment-id", enrichment_id,
    ])
    allowed = (code == 0 and out.strip() == "ALLOW")
    out_doc["enforcement"] = {
        "allowed": allowed,
        "action": "run_enrichment",
        "details": "ALLOW" if allowed else (err.strip() or "DENY"),
    }

    if not allowed:
        out_doc["result"]["status"] = "denied"
        Path(args.out_json).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
        print(f"OK: wrote {args.out_json}")
        return 0

    # Execute pipeline exactly as plan declares (but we require it matches our known script for now)
    pipeline_script = Path(plan["enrichment"]["pipeline_script"])
    if pipeline_script != HAYABUSA_PIPELINE:
        raise SystemExit(f"FAIL: plan pipeline_script not allowed: {pipeline_script} (expected {HAYABUSA_PIPELINE})")

    evtx_dir = plan["baseline"]["evtx_dir"]
    tier = plan["enrichment"].get("tier", "quick")
    run_must([str(HAYABUSA_PIPELINE), evtx_dir, "--tier", tier])

    # Resolve hayabusa run_id via LATEST pointer
    latest_file = Path("outputs/jsonl/hayabusa_evtx/LATEST")
    if not latest_file.is_file():
        raise SystemExit(f"FAIL: hayabusa did not write LATEST: {latest_file}")
    run_id = latest_file.read_text(encoding="utf-8").strip()

    manifest_path = Path(f"outputs/jsonl/hayabusa_evtx/{run_id}/manifest.json")
    if not manifest_path.is_file():
        raise SystemExit(f"FAIL: hayabusa manifest missing: {manifest_path}")

    out_doc["result"] = {"status": "ok", "run_id": run_id, "manifest_path": str(manifest_path)}

    Path(args.out_json).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    print(f"OK: wrote {args.out_json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

