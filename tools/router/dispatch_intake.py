#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

INTAKE_SCHEMA = Path("contracts/intake.schema.json")
CASE_SCHEMA = Path("contracts/case.schema.json")
DISPATCH_SCHEMA = Path("contracts/dispatch.schema.json")

VALIDATE_INTAKE = Path("tools/contracts/validate_intake.py")
VALIDATE_DISPATCH = Path("tools/contracts/validate_dispatch.py")

PIPELINES = {
    "chainsaw_evtx": {
        "script": Path("pipelines/chainsaw_evtx/run.sh"),
        "latest_file": Path("outputs/jsonl/chainsaw_evtx/LATEST"),
        "manifest_path": lambda run_id: Path(f"outputs/jsonl/chainsaw_evtx/{run_id}/manifest.json"),
    }
}

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def run(cmd, cwd=None) -> None:
    p = subprocess.run(cmd, cwd=cwd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic intake dispatcher (no MCP)")
    ap.add_argument("--intake-json", required=True, help="path to intake.json")
    args = ap.parse_args()

    intake_json = Path(args.intake_json)
    if not intake_json.is_file():
        print(f"FAIL: intake.json not found: {intake_json}", file=sys.stderr)
        return 2

    raw_data = read_json(intake_json)
    
    # Schema Detection & Validation (V30 Compatibility)
    if "case_id" in raw_data:
        # Validate against Case Schema
        run([str(VALIDATE_INTAKE), str(CASE_SCHEMA), str(intake_json)])
        intake_id = raw_data["case_id"]
        # For dispatch, we need a primary evidence path. 
        # We'll take the first staged evidence or fallback to original.
        staged = [e for e in raw_data.get("evidence", []) if e.get("root") == "staged"]
        if staged:
            evidence_path = str(Path(raw_data["evidence_roots"]["staged"]) / staged[0]["relpath"])
            kind = staged[0]["type"]
        else:
            evidence_path = str(Path(raw_data["evidence_roots"]["original"]) / raw_data["evidence"][0]["relpath"])
            kind = raw_data["evidence"][0]["type"]
            
        # Infer recommended pipeline
        rec = "chainsaw_evtx" if "evtx" in kind or "windows_evtx" in kind else None
    else:
        # Legacy intake.json: Validate against Intake Schema
        run([str(VALIDATE_INTAKE), str(INTAKE_SCHEMA), str(intake_json)])
        intake = raw_data
        intake_id = intake["intake_id"]
        rec = intake["classification"]["recommended_pipeline"]
        evidence_path = intake["inputs"]["paths"][0]

    dispatch = {
        "intake_id": intake_id,
        "timestamp_utc": utc_now_z(),
        "decision": {
            "recommended_pipeline": rec,
            "evidence_path": evidence_path,
            "status": "dispatch" if rec else "skip"
        },
        "result": {
            "ok": False,
            "run_id": None,
            "manifest_path": None
        }
    }

    # Execute pipeline if recommended
    if rec:
        if rec not in PIPELINES:
            print(f"FAIL: unsupported recommended_pipeline: {rec}", file=sys.stderr)
            return 3

        cfg = PIPELINES[rec]
        script = cfg["script"]
        if not script.is_file():
            print(f"FAIL: pipeline script missing: {script}", file=sys.stderr)
            return 4

        # Run the pipeline (pipeline itself enforces validation + artifacts)
        run([str(script), evidence_path])

        # Resolve run_id from LATEST
        latest_file = cfg["latest_file"]
        if not latest_file.is_file():
            print(f"FAIL: pipeline did not write LATEST file: {latest_file}", file=sys.stderr)
            return 5

        run_id = latest_file.read_text(encoding="utf-8").strip()
        manifest_path = cfg["manifest_path"](run_id)

        # Validate manifest again as a router-level gate
        run(["tools/contracts/validate_manifest.py", "contracts/manifest.schema.json", str(manifest_path)])

        dispatch["result"] = {
            "ok": True,
            "run_id": run_id,
            "manifest_path": str(manifest_path)
        }

    # Write dispatch.json next to intake.json
    out_path = intake_json.parent / "dispatch.json"
    out_path.write_text(json.dumps(dispatch, indent=2), encoding="utf-8")
    print(f"OK: wrote {out_path}")

    # Validate dispatch artifact (hard gate)
    run([str(VALIDATE_DISPATCH), str(DISPATCH_SCHEMA), str(out_path)])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

