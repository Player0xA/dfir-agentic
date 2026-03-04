#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REGISTRY = Path(".agents/registry.json")

SELECT_AGENT = Path("tools/router/select_agent.py")
ENFORCE = Path("tools/router/enforce_capabilities.py")
DISPATCH = Path("tools/router/dispatch_intake.py")

# NEW: optional stages
ENRICH_DECIDER = Path("tools/enrich/decide_enrichment.py")
ENRICH_RUNNER = Path("tools/enrich/run_hayabusa_if_needed.py")
PLASO_RUNNER = Path("pipelines/plaso_evtx/run.sh")
MERGE_TOOL = Path("tools/merge/merge_case_findings.py")

APPCOMPAT_RUNNER = Path("pipelines/appcompatcache/run.sh")
MFTECMD_RUNNER = Path("pipelines/mftecmd/run.sh")
RBCMD_RUNNER = Path("pipelines/rbcmd/run.sh")
LECMD_RUNNER = Path("pipelines/lecmd/run.sh")
RFC_RUNNER = Path("pipelines/recentfilecache/run.sh")

VALIDATE_AUTO = Path("tools/contracts/validate_auto.py")
AUTO_SCHEMA = Path("contracts/auto.schema.json")

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def run_capture(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def run_must(cmd):
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def main() -> int:
    ap = argparse.ArgumentParser(description="Autonomous local protocol runner (no MCP)")
    ap.add_argument("--intake-json", required=True)
    ap.add_argument("--task", help="Investigative intent/task description")

    # NEW: deterministic orchestration flags
    ap.add_argument("--enrichment-policy", choices=["always", "never"], default="never",
                    help="whether to run enrichment stage after baseline (default: never)")
    ap.add_argument("--run-merge", action="store_true",
                    help="run merge stage to produce case_findings.json + case_manifest.json")
    ap.add_argument("--playbook", help="Manual playbook override (e.g. memory_triage_v1)")
    ap.add_argument("--merge-dedupe", action="store_true",
                    help="enable merge dedupe (same tool/rule_id/event_refs)")

    args = ap.parse_args()

    intake_json = Path(args.intake_json)
    if not intake_json.is_file():
        print(f"FAIL: intake.json not found: {intake_json}", file=sys.stderr)
        return 2

    intake = load_json(intake_json)
    
    # Schema Detection (V30 Compatibility)
    if "case_id" in intake:
        intake_id = intake["case_id"]
        # Inferred classification based on evidence
        evidence_types = [e["type"] for e in intake.get("evidence", [])]
        ev_names = [e["name"].lower() for e in intake.get("evidence", [])]
        
        if "evtx" in evidence_types or "evtx_dir" in evidence_types:
            kind = "windows_evtx_dir"
            rec = "chainsaw_evtx"
        elif any("system" in name for name in ev_names):
            kind = "windows_registry"
            rec = "appcompatcache"
        elif any("$mft" in name or "mft" in name for name in ev_names):
            kind = "windows_mft"
            rec = "mftecmd"
        elif any("recycle" in name or "$i" in name for name in ev_names):
            kind = "windows_recycle_bin"
            rec = "rbcmd"
        elif any(".lnk" in name for name in ev_names):
            kind = "windows_lnk"
            rec = "lecmd"
        elif any("recentfilecache" in name.lower() for name in ev_names):
            kind = "windows_recentfilecache"
            rec = "recentfilecache"
        else:
            kind = "generic"
            rec = None
    else:
        # Legacy intake.json
        intake_id = intake["intake_id"]
        kind = intake["classification"]["kind"]
        rec = intake["classification"]["recommended_pipeline"]

    auto_id = str(uuid.uuid4())
    ts = utc_now_z()

    # 1) Select agent deterministically
    select_cmd = [str(SELECT_AGENT), "--intake-json", str(intake_json), "--registry", str(REGISTRY)]
    if args.task:
        select_cmd.extend(["--task", args.task])
    
    code, out, err = run_capture(select_cmd)
    if code != 0:
        print(err, file=sys.stderr)
        return code
    sel = json.loads(out)
    agent_id = sel.get("selected_agent", "triage_agent")
    playbook_id = args.playbook if args.playbook else sel.get("selected_playbook", "initial_access_v1")

    # 2) Enforce capability (dispatch pipeline only if recommended)
    if rec:
        code, out2, err2 = run_capture([str(ENFORCE), "--registry", str(REGISTRY),
                                        "--agent-id", agent_id, "--action", "dispatch_pipeline",
                                        "--pipeline-id", rec])
        allowed = (code == 0 and out2.strip() == "ALLOW")
        enforcement = {
            "allowed": allowed,
            "action": "dispatch_pipeline",
            "details": ("ALLOW" if allowed else err2.strip() or "DENY")
        }
    else:
        enforcement = {"allowed": True, "action": "skip", "details": "no recommended pipeline"}

    dispatch_block = {"status": "skipped", "dispatch_json": None, "run_id": None, "manifest_path": None}

    # 3) Execute dispatch if allowed
    if enforcement["action"] == "dispatch_pipeline" and enforcement["allowed"]:
        dispatch_cmd = [str(DISPATCH), "--intake-json", str(intake_json), "--playbook", playbook_id]
        if args.task:
            dispatch_cmd.extend(["--task", args.task])
        run_must(dispatch_cmd)
        dispatch_json = intake_json.parent / "dispatch.json"
        d = load_json(dispatch_json)
        dispatch_block = {
            "status": "ok" if d["result"]["ok"] else "error",
            "dispatch_json": str(dispatch_json),
            "run_id": d["result"]["run_id"],
            "manifest_path": d["result"]["manifest_path"]
        }
    elif enforcement["action"] == "dispatch_pipeline" and not enforcement["allowed"]:
        dispatch_block = {"status": "denied", "dispatch_json": None, "run_id": None, "manifest_path": None}

    # 4) Initialize auto_doc
    auto_doc = {
        "auto_id": auto_id,
        "timestamp_utc": ts,
        "intake": {"intake_id": intake_id, "intake_json": str(intake_json)},
        "selection": {"selected_agent": agent_id, "selected_playbook": playbook_id, "kind": kind},
        "enforcement": enforcement,
        "dispatch": dispatch_block,
        "stages": {
            "plaso": "skipped",
            "appcompatcache": "skipped",
            "mftecmd": "skipped",
            "rbcmd": "skipped",
            "lecmd": "skipped",
            "recentfilecache": "skipped",
            "enrichment": "skipped",
            "merge": "skipped"
        }
    }
    out_path = intake_json.parent / "auto.json"
    out_path.write_text(json.dumps(auto_doc, indent=2), encoding="utf-8")

    # --- Phase: Automated Super Timeline (Plaso) ---
    if dispatch_block["status"] == "ok":
        manifest_path_str = dispatch_block.get("manifest_path")
        manifest_path = Path(manifest_path_str) if manifest_path_str else None
        
        # Plaso usually needs a manifest to run, but we can also infer from intake
        if manifest_path and manifest_path.is_file():
            # Step 8/9: Resolve primary evidence for Plaso
            if "case_id" in intake:
                staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
                evtx_dir = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"] if staged else None
            else:
                manifest = load_json(manifest_path)
                evtx_dir = manifest.get("inputs", {}).get("evtx_dir")
                
            if evtx_dir:
                print("INFO: starting plaso pipeline")
                auto_doc["stages"]["plaso"] = "running"
                try:
                    # Use deterministic run_id for plaso so the Map can find it
                    plaso_run_id = f"{intake_id}-plaso"
                    run_must([str(PLASO_RUNNER), plaso_run_id, ts, str(evtx_dir), str(intake_json.parent)])
                    
                    src_plaso = intake_json.parent / plaso_run_id / "case.plaso"
                    dest_plaso = intake_json.parent / f"{intake_id}.plaso"
                    if src_plaso.exists():
                        import shutil
                        shutil.move(str(src_plaso), str(dest_plaso))
                    auto_doc["stages"]["plaso"] = "ok"
                except Exception as e:
                    print(f"WARNING: Plaso pipeline failed: {e}", file=sys.stderr)
                    auto_doc["stages"]["plaso"] = f"error: {e}"

    # --- Phase: Automated AppCompatCache ---
    if rec == "appcompatcache" and dispatch_block["status"] == "ok":
        print("INFO: starting appcompatcache pipeline")
        auto_doc["stages"]["appcompatcache"] = "running"
        try:
            staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                # Find the SYSTEM hive or assume the passed dir is the hive
                system_hive = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"]
                acp_run_id = f"{intake_id}-acp"
                run_must([str(APPCOMPAT_RUNNER), acp_run_id, ts, str(system_hive)])
                auto_doc["stages"]["appcompatcache"] = "ok"
            else:
                auto_doc["stages"]["appcompatcache"] = "skipped (no evidence)"
        except Exception as e:
            print(f"WARNING: AppCompatCache pipeline failed: {e}", file=sys.stderr)
            auto_doc["stages"]["appcompatcache"] = f"error: {e}"

    # --- Phase: Automated MFTECmd ---
    if rec == "mftecmd" and dispatch_block["status"] == "ok":
        print("INFO: starting mftecmd pipeline")
        auto_doc["stages"]["mftecmd"] = "running"
        try:
            staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                mft_file = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"]
                mft_run_id = f"{intake_id}-mft"
                run_must([str(MFTECMD_RUNNER), mft_run_id, ts, str(mft_file)])
                auto_doc["stages"]["mftecmd"] = "ok"
            else:
                auto_doc["stages"]["mftecmd"] = "skipped (no evidence)"
        except Exception as e:
            print(f"WARNING: MFTECmd pipeline failed: {e}", file=sys.stderr)
            auto_doc["stages"]["mftecmd"] = f"error: {e}"

    # --- Phase: Automated RBCmd ---
    if rec == "rbcmd" and dispatch_block["status"] == "ok":
        print("INFO: starting rbcmd pipeline")
        auto_doc["stages"]["rbcmd"] = "running"
        try:
            staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                target_path = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"]
                rb_run_id = f"{intake_id}-rb"
                run_must([str(RBCMD_RUNNER), rb_run_id, ts, str(target_path)])
                auto_doc["stages"]["rbcmd"] = "ok"
            else:
                auto_doc["stages"]["rbcmd"] = "skipped (no evidence)"
        except Exception as e:
            print(f"WARNING: RBCmd pipeline failed: {e}", file=sys.stderr)
            auto_doc["stages"]["rbcmd"] = f"error: {e}"

    # --- Phase: Automated LECmd ---
    if rec == "lecmd" and dispatch_block["status"] == "ok":
        print("INFO: starting lecmd pipeline")
        auto_doc["stages"]["lecmd"] = "running"
        try:
            staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                target_path = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"]
                le_run_id = f"{intake_id}-le"
                run_must([str(LECMD_RUNNER), le_run_id, ts, str(target_path)])
                auto_doc["stages"]["lecmd"] = "ok"
            else:
                auto_doc["stages"]["lecmd"] = "skipped (no evidence)"
        except Exception as e:
            print(f"WARNING: LECmd pipeline failed: {e}", file=sys.stderr)
            auto_doc["stages"]["lecmd"] = f"error: {e}"

    # --- Phase: Automated RecentFileCacheParser ---
    if rec == "recentfilecache" and dispatch_block["status"] == "ok":
        print("INFO: starting recentfilecache pipeline")
        auto_doc["stages"]["recentfilecache"] = "running"
        try:
            staged = [e for e in intake.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                target_path = Path(intake["evidence_roots"]["staged"]) / staged[0]["relpath"]
                rfc_run_id = f"{intake_id}-rfc"
                run_must([str(RFC_RUNNER), rfc_run_id, ts, str(target_path)])
                auto_doc["stages"]["recentfilecache"] = "ok"
            else:
                auto_doc["stages"]["recentfilecache"] = "skipped (no evidence)"
        except Exception as e:
            print(f"WARNING: RecentFileCache pipeline failed: {e}", file=sys.stderr)
            auto_doc["stages"]["recentfilecache"] = f"error: {e}"

    # 6) Optional enrichment stage
    if args.enrichment_policy == "always":
        plan_json = intake_json.parent / "enrichment_plan.json"
        enrich_json = intake_json.parent / "enrichment.json"
        auto_doc["stages"]["enrichment"] = "running"

        if not ENRICH_DECIDER.is_file():
            print(f"FAIL: enrichment decider not found: {ENRICH_DECIDER}", file=sys.stderr)
            return 2
        
        # Decide (deterministic depth check)
        run_must([str(ENRICH_DECIDER), "--auto-json", str(out_path), "--out-plan", str(plan_json)])
        
        if not ENRICH_RUNNER.is_file():
            print(f"FAIL: enrichment runner not found: {ENRICH_RUNNER}", file=sys.stderr)
            return 2
            
        # Run
        try:
            run_must([str(ENRICH_RUNNER), "--plan-json", str(plan_json), "--out-json", str(enrich_json)])
            auto_doc["stages"]["enrichment"] = "ok"
        except Exception as e:
            auto_doc["stages"]["enrichment"] = f"error: {e}"

    # 7) Optional merge stage
    if args.run_merge and dispatch_block.get("manifest_path"):
        auto_doc["stages"]["merge"] = "running"
        if not MERGE_TOOL.is_file():
            print(f"FAIL: merge tool not found: {MERGE_TOOL}", file=sys.stderr)
            return 2
        cmd = [str(MERGE_TOOL), "--intake-dir", str(intake_json.parent)]
        if args.merge_dedupe:
            cmd.append("--dedupe")
        
        try:
            run_must(cmd)
            auto_doc["stages"]["merge"] = "ok"
        except Exception as e:
            auto_doc["stages"]["merge"] = f"error: {e}"
            print(f"WARNING: Merge stage failed: {e}", file=sys.stderr)
    elif args.run_merge:
        # User requested merge, but we lack a manifest (likely pipeline failure)
        auto_doc["stages"]["merge"] = "skipped (missing baseline manifest)"

    # 8) Final write of auto.json (full state)
    out_path.write_text(json.dumps(auto_doc, indent=2), encoding="utf-8")
    print(f"OK: wrote {out_path}")

    # 9) Validate auto.json
    run_must([str(VALIDATE_AUTO), str(AUTO_SCHEMA), str(out_path)])

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

