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
PLAYBOOKS_YAML = Path("contracts/playbooks.yaml")

VALIDATE_INTAKE = Path("tools/contracts/validate_intake.py")
VALIDATE_DISPATCH = Path("tools/contracts/validate_dispatch.py")

PIPELINES = {
    "chainsaw_evtx": {
        "script": Path("pipelines/chainsaw_evtx/run.sh"),
        "latest_file": Path("outputs/jsonl/chainsaw_evtx/LATEST"),
        "manifest_path": lambda run_id: Path(f"outputs/jsonl/chainsaw_evtx/{run_id}/manifest.json"),
    },
    "hayabusa_evtx": {
        "script": Path("pipelines/hayabusa_evtx/run.sh"),
        "latest_file": Path("outputs/jsonl/hayabusa_evtx/LATEST"),
        "manifest_path": lambda run_id: Path(f"outputs/jsonl/hayabusa_evtx/{run_id}/manifest.json"),
    },
    "plaso_evtx": {
        "script": Path("pipelines/plaso_evtx/run.sh"),
        "latest_file": None, # Handled specially
        "manifest_path": None,
    }
}

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def run(cmd, cwd=None) -> None:
    p = subprocess.run(cmd, cwd=cwd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)

def run_catch(cmd, cwd=None) -> int:
    p = subprocess.run(cmd, cwd=cwd, text=True)
    return p.returncode

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def write_gap_to_case_notes(intake_json: Path, source: str, description: str):
    """V37: If a playbook step fails due to missing artifacts, write a GAP claim to case_notes."""
    case_dir = intake_json.parent
    notes_path = case_dir / "case_notes.json"
    if notes_path.is_file():
        try:
            notes = json.loads(notes_path.read_text(encoding="utf-8"))
            notes["claims"].append({
                "type": "GAP",
                "focus": source,
                "content": description,
                "confidence": "HIGH",
                "status": "OPEN",
                "impact": "CRITICAL"
            })
            notes_path.write_text(json.dumps(notes, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"Failed to write GAP claim to {notes_path}: {e}", file=sys.stderr)

def load_playbooks_yaml(path: Path):
    """Fallback manual YAML parser to avoid imposing PyYAML dependency on the env."""
    lines = path.read_text(encoding="utf-8").splitlines()
    playbooks = {}
    curr_pb = None
    for line in lines:
        line_s = line.strip()
        if not line_s or line_s.startswith("#") or line.startswith("playbooks:"):
            continue
        if line.startswith("  ") and not line.startswith("    "):
            curr_pb = line_s.strip(":")
            playbooks[curr_pb] = {"steps": []}
        elif line.startswith("      - run:"):
            val = line.split("- run:")[1].strip()
            if curr_pb:
                playbooks[curr_pb]["steps"].append({"run": val})
    return {"playbooks": playbooks}

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic intake dispatcher (no MCP)")
    ap.add_argument("--intake-json", required=True, help="path to intake.json")
    ap.add_argument("--playbook", default="initial_access_v1", help="Playbook to execute")
    ap.add_argument("--task", help="Investigative intent")
    args = ap.parse_args()

    intake_json = Path(args.intake_json)
    if not intake_json.is_file():
        print(f"FAIL: intake.json not found: {intake_json}", file=sys.stderr)
        return 2

    raw_data = read_json(intake_json)
    
    # Schema Detection & Validation (V30 Compatibility)
    if "case_id" in raw_data:
        run([str(VALIDATE_INTAKE), str(CASE_SCHEMA), str(intake_json)])
        intake_id = raw_data["case_id"]
        case_dir = intake_json.parent
        staged = [e for e in raw_data.get("evidence", []) if e.get("root") == "staged"]
        if staged:
            evidence_path = str(Path(raw_data["evidence_roots"]["staged"]) / staged[0]["relpath"])
            kind = staged[0]["type"]
        else:
            evidence_path = str(Path(raw_data["evidence_roots"]["original"]) / raw_data["evidence"][0]["relpath"])
            kind = raw_data["evidence"][0]["type"]
    else:
        run([str(VALIDATE_INTAKE), str(INTAKE_SCHEMA), str(intake_json)])
        intake = raw_data
        intake_id = intake["intake_id"]
        evidence_path = intake["inputs"]["paths"][0]
        case_dir = intake_json.parent

    # Load playbooks without PyYAML
    if not PLAYBOOKS_YAML.is_file():
        print(f"FAIL: playbooks.yaml not found: {PLAYBOOKS_YAML}", file=sys.stderr)
        return 2
        
    playbooks_doc = load_playbooks_yaml(PLAYBOOKS_YAML)
        
    playbooks = playbooks_doc.get("playbooks", {})
    if args.playbook not in playbooks:
        print(f"FAIL: Selected playbook not found: {args.playbook}", file=sys.stderr)
        return 3
        
    selected_playbook_spec = playbooks[args.playbook]
    steps_to_run = selected_playbook_spec.get("steps", [])

    dispatch = {
        "intake_id": intake_id,
        "timestamp_utc": utc_now_z(),
        "decision": {
            "recommended_pipeline": steps_to_run[0]["run"] if steps_to_run else None,
            "selected_playbook": args.playbook,
            "evidence_path": evidence_path,
            "status": "dispatch" if steps_to_run else "skip"
        },
        "result": {
            "ok": False,
            "run_id": None,
            "manifest_path": None,
            "steps": []
        }
    }

    # Execute playbook steps
    primary_run_id = None
    primary_manifest = None
    step_history = []
    
    overall_ok = True

    for step in steps_to_run:
        pipeline_id = step.get("run")
        if pipeline_id not in PIPELINES:
            step_history.append(f"{pipeline_id}: unsupported")
            overall_ok = False
            continue

        cfg = PIPELINES[pipeline_id]
        script = cfg["script"]
        if not script.is_file():
            step_history.append(f"{pipeline_id}: script missing")
            overall_ok = False
            continue

        print(f"\n>> Running playbook step: {pipeline_id}")
        
        # Determine Arguments based on Pipeline
        if pipeline_id == "plaso_evtx":
            plaso_run_id = f"{intake_id}-plaso"
            cmd = [str(script), plaso_run_id, utc_now_z(), evidence_path, str(case_dir)]
        else:
            cmd = [str(script), evidence_path]

        # V37: Handle failures gracefully and generate GAP entries
        rc = run_catch(cmd)
        
        if rc != 0:
            step_history.append(f"{pipeline_id}: failed (rc={rc})")
            
            # V37 GAP handling ("no 4688" or general pipeline failure)
            if "chainsaw" in pipeline_id or "hayabusa" in pipeline_id:
                 write_gap_to_case_notes(
                     intake_json, 
                     pipeline_id, 
                     f"Pipeline {pipeline_id} failed during playbook execution. Expected logs (e.g., 4688) may be missing, corrupted, or unsupported."
                 )
            
            # Continue to next step instead of hard failure
            continue
            
        step_history.append(f"{pipeline_id}: ok")

        # Resolve run_id from LATEST if applicable
        if cfg["latest_file"] and cfg["latest_file"].is_file():
            run_id = cfg["latest_file"].read_text(encoding="utf-8").strip()
            manifest_path = cfg["manifest_path"](run_id)
            run(["tools/contracts/validate_manifest.py", "contracts/manifest.schema.json", str(manifest_path)])
            
            if primary_run_id is None:
                primary_run_id = run_id
                primary_manifest = str(manifest_path)
                
        elif pipeline_id == "plaso_evtx":
            src_plaso = case_dir / f"{intake_id}-plaso" / "case.plaso"
            dest_plaso = case_dir / f"{intake_id}.plaso"
            if src_plaso.exists():
                import shutil
                shutil.move(str(src_plaso), str(dest_plaso))

    dispatch["result"] = {
        "ok": overall_ok,
        "run_id": primary_run_id,
        "manifest_path": primary_manifest,
        "steps": step_history
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
