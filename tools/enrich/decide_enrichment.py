#!/usr/bin/env python3
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
sys.path.append(str(Path(__file__).parent))
import policy_engine

ENRICHMENT_ID = "hayabusa_evtx"
PIPELINE_SCRIPT = "pipelines/hayabusa_evtx/run.sh"

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def must_file(p: Path, label: str):
    if not p.is_file():
        raise SystemExit(f"FAIL: {label} not found: {p}")

def main() -> int:
    ap = argparse.ArgumentParser(description="Decide enrichment plan from baseline outputs")
    ap.add_argument("--auto-json", required=True)
    ap.add_argument("--out-plan", required=True)
    ap.add_argument("--threshold-detections", type=int, default=50)
    args = ap.parse_args()

    auto_path = Path(args.auto_json)
    must_file(auto_path, "auto.json")
    auto = load_json(auto_path)

    agent_id = auto["selection"]["selected_agent"]

    base_manifest_path = Path(auto.get("dispatch", {}).get("manifest_path") or "")
    if not str(base_manifest_path):
        print("FAIL: auto.json missing dispatch.manifest_path", file=sys.stderr)
        return 2
    must_file(base_manifest_path, "baseline manifest.json")
    base_manifest = load_json(base_manifest_path)

    evtx_dir = base_manifest.get("inputs", {}).get("evtx_dir")
    if not evtx_dir:
        print(f"FAIL: baseline manifest missing inputs.evtx_dir: {base_manifest_path}", file=sys.stderr)
        return 2

    triage_path = Path(base_manifest.get("artifacts", {}).get("triage_json", {}).get("path", ""))
    if not triage_path.is_file():
        candidate = base_manifest_path.parent / "triage.json"
        if candidate.is_file():
            triage_path = candidate
        else:
            print(f"FAIL: baseline triage.json not found: {base_manifest_path}", file=sys.stderr)
            return 2

    triage = load_json(triage_path)

    count = None
    source = None
    checked = []

    for keypath in [
        ("counts", "total_findings"),
        ("counts", "total_detections"),
        ("summary", "detections"),
        ("detections_count",),
    ]:
        cur = triage
        ok = True
        for k in keypath:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        checked.append(".".join(keypath))
        if ok and isinstance(cur, int):
            count = cur
            source = "path:" + ".".join(keypath)
            break

    if count is None:
        count = 0
        source = "default:0"

    # Delegate to the Structured Policy Engine
    decision = policy_engine.evaluate(triage, threshold_detections=args.threshold_detections)
    
    tier = decision["tier"]
    should_run = decision["should_run"]
    reason = decision["reason"]

    plan = {
        "plan_id": str(uuid.uuid4()),
        "timestamp_utc": utc_now_z(),
        "agent_id": agent_id,
        "baseline": {
            "auto_json": str(auto_path),
            "baseline_manifest_path": str(base_manifest_path),
            "evtx_dir": str(evtx_dir)
        },
        "enrichment": {
            "enrichment_id": ENRICHMENT_ID,
            "pipeline_script": PIPELINE_SCRIPT,
            "args": [str(evtx_dir)],
            "tier": tier
        },
        "decision": {
            "should_run": should_run,
            "reason": reason,
            "policy": {"mode": "agent_decision"}
        }
    }

    out_plan = Path(args.out_plan)
    out_plan.parent.mkdir(parents=True, exist_ok=True)
    out_plan.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"OK: wrote {out_plan}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

