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

# Optional stages
ENRICH_DECIDER = Path("tools/enrich/decide_enrichment.py")
ENRICH_RUNNER = Path("tools/enrich/run_hayabusa_if_needed.py")
MERGE_TOOL = Path("tools/merge/merge_case_findings.py")

VALIDATE_AUTO = Path("tools/contracts/validate_auto.py")
AUTO_SCHEMA = Path("contracts/auto.schema.json")

# Dynamic Tool Registry - Add new tools here (no code changes needed)
# Format: "tool_id": {"script": Path, "evidence_arg": "staged|original", "run_id_suffix": "-suffix"}
TOOL_REGISTRY = {
    "chainsaw_evtx": {
        "script": Path("pipelines/chainsaw_evtx/run.sh"),
        "evidence_arg": "original",  # Uses original evidence path
        "run_id_suffix": "",
    },
    "hayabusa_evtx": {
        "script": Path("pipelines/hayabusa_evtx/run.sh"),
        "evidence_arg": "original",
        "run_id_suffix": "",
    },
    "plaso_evtx": {
        "script": Path("pipelines/plaso_evtx/run.sh"),
        "evidence_arg": "staged",  # Uses staged path
        "run_id_suffix": "-plaso",
    },
    "appcompatcache": {
        "script": Path("pipelines/appcompatcache/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-acp",
        "file_patterns": ["SYSTEM"],  # Registry hive file
        "description": "AppCompatCache from SYSTEM hive"
    },
    "mftecmd": {
        "script": Path("pipelines/mftecmd/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-mft",
        "file_patterns": ["$MFT", "*.mft"],  # Master File Table
        "description": "Parse $MFT for file system artifacts"
    },
    "rbcmd": {
        "script": Path("pipelines/rbcmd/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-rb",
        "file_patterns": ["$I*", "*-$I*"],  # Recycle Bin $I files
        "description": "Recycle Bin artifact analysis"
    },
    "lecmd": {
        "script": Path("pipelines/lecmd/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-le",
        "file_patterns": ["*.lnk"],  # Windows shortcuts
        "description": "LNK file (shortcut) analysis"
    },
    "recentfilecache": {
        "script": Path("pipelines/recentfilecache/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-rfc",
        "file_patterns": ["RecentFileCache.bcf", "*.bcf"],
        "description": "RecentFileCache parsing"
    },
    "jlecmd": {
        "script": Path("pipelines/jlecmd/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-jl",
        "file_patterns": ["*.destinations-ms", "*.customDestinations-ms", "*Destinations"],
        "description": "Jump List analysis"
    },
    "recmd": {
        "script": Path("pipelines/recmd/run.sh"),
        "evidence_arg": "staged",
        "run_id_suffix": "-re",
        "file_patterns": ["NTUSER.DAT", "UsrClass.dat", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "*.dat"],
        "description": "Registry hive analysis"
    },
}

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def run_capture(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def run_must(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        print(f"FAILED CMD: {' '.join(cmd)}", file=sys.stderr)
        if p.stdout:
            print(f"STDOUT:\n{p.stdout}", file=sys.stderr)
        if p.stderr:
            print(f"STDERR:\n{p.stderr}", file=sys.stderr)
        raise SystemExit(p.returncode)

def resolve_evidence_path(intake_data: dict, evidence_arg: str) -> tuple[Path | None, str]:
    """Resolve the evidence path from intake data.
    
    Args:
        intake_data: The intake.json data
        evidence_arg: "staged" or "original" - which evidence root to use
        
    Returns:
        Tuple of (resolved_path, evidence_description)
    """
    has_case_id = "case_id" in intake_data
    
    if has_case_id:
        evidence_list = intake_data.get("evidence", [])
        staged = [e for e in evidence_list if e.get("root") == "staged"]
        original = [e for e in evidence_list if e.get("root") == "original"]
        
        if evidence_arg == "staged" and staged:
            base = intake_data.get("evidence_roots", {}).get("staged")
            if base:
                return Path(base) / staged[0]["relpath"], f"staged/{staged[0]['relpath']}"
        elif evidence_arg == "original" and original:
            base = intake_data.get("evidence_roots", {}).get("original")
            if base:
                return Path(base) / original[0]["relpath"], f"original/{original[0]['relpath']}"
        elif evidence_arg == "staged" and original:
            # Fallback to original if staged not available
            base = intake_data.get("evidence_roots", {}).get("original")
            if base:
                return Path(base) / original[0]["relpath"], f"original/{original[0]['relpath']}"
    else:
        # Legacy intake format
        paths = intake_data.get("inputs", {}).get("paths", [])
        if paths:
            return Path(paths[0]), paths[0]
    
    return None, "unknown"

def find_evidence_files(evidence_path: Path, file_patterns: list) -> tuple[list[Path], str]:
    """Find specific evidence files matching patterns in a directory or return the path itself.
    
    For file-based tools (mftecmd, rbcmd, etc.), searches for files matching patterns.
    For directory-based tools or if given a file directly, returns the path as-is.
    
    Args:
        evidence_path: Directory or file path from resolve_evidence_path()
        file_patterns: List of glob patterns to search for (e.g., ["$MFT", "*.mft"])
        
    Returns:
        Tuple of (list of matching file paths, status message)
        Status message describes what was found or why nothing was found
    """
    # If evidence_path is already a file, return it directly
    if evidence_path.is_file():
        return [evidence_path], f"Using file: {evidence_path.name}"
    
    # If it's a directory and we have patterns, search for files
    if evidence_path.is_dir() and file_patterns:
        found_files = []
        search_summary = []
        
        for pattern in file_patterns:
            # Search in the directory and all subdirectories
            matches = list(evidence_path.rglob(pattern))
            # Also try case-insensitive search for patterns like $MFT
            if not matches and pattern.startswith('$'):
                # Try lowercase version for case-insensitive filesystems
                matches = list(evidence_path.rglob(pattern.lower()))
            
            if matches:
                for match in matches:
                    if match.is_file() and match not in found_files:
                        found_files.append(match)
                        search_summary.append(f"{pattern} -> {match.name}")
        
        if found_files:
            # Sort files by path for consistent ordering
            found_files.sort(key=lambda p: str(p))
            return found_files, f"Found {len(found_files)} files: {', '.join(search_summary[:3])}" + ("..." if len(search_summary) > 3 else "")
        else:
            # No files found - return empty silently (no error message)
            return [], ""
    
    # If directory but no patterns, return directory path as-is
    if evidence_path.is_dir():
        return [evidence_path], f"Using directory: {evidence_path.name}"
    
    # Path doesn't exist
    return [], ""

def write_progress_update(case_dir: Path, tool_id: str, status: str, progress: int = 0, 
                          current_action: str = "", details = None):
    """Write real-time progress update to progress.json for dashboard polling.
    
    Args:
        case_dir: Path to case directory (outputs/intake/{case_id})
        tool_id: Tool identifier (e.g., "plaso_evtx", "mftecmd")
        status: "initializing", "running", "completed", "error"
        progress: 0-100 progress percentage
        current_action: Human-readable action description
        details: Optional dict with additional details (files_processed, total_files, etc.)
    """
    try:
        progress_file = case_dir / "progress.json"
        
        # Initialize details dict
        details_dict = details if details else {}
        
        progress_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_id": tool_id,
            "status": status,
            "progress": progress,
            "current_action": current_action,
            "details": details_dict
        }
        
        # Read existing data to append history
        if progress_file.exists():
            try:
                with open(progress_file, "r") as f:
                    existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
            except:
                existing = []
        else:
            existing = []
        
        # Append new update (keep last 100 entries)
        existing.append(progress_data)
        existing = existing[-100:]
        
        with open(progress_file, "w") as f:
            json.dump(existing, f, indent=2)
            
    except Exception as e:
        print(f"[WARN] Failed to write progress update: {e}", file=sys.stderr)


def run_tool_dynamically(
    tool_id: str,
    intake_data: dict,
    intake_id: str,
    ts: str,
    auto_doc: dict,
    out_path: Path,
    selected_tools: list[str] | None
) -> dict:
    """Dynamically run a tool based on registry configuration.
    
    Args:
        tool_id: The tool identifier (e.g., "mftecmd", "recmd")
        intake_data: The intake.json data
        intake_id: The case UUID
        ts: Timestamp string
        auto_doc: The auto.json document to update
        out_path: Path to auto.json
        selected_tools: List of selected tools or None for allow-all
        
    Returns:
        Updated auto_doc
    """
    # Check if tool is in registry
    if tool_id not in TOOL_REGISTRY:
        print(f"[WARN] Tool '{tool_id}' not in registry, skipping")
        auto_doc["stages"][tool_id] = "skipped (not in registry)"
        return auto_doc
    
    tool_config = TOOL_REGISTRY[tool_id]
    script = tool_config["script"]
    evidence_arg = tool_config.get("evidence_arg", "original")
    run_id_suffix = tool_config.get("run_id_suffix", "")
    file_patterns = tool_config.get("file_patterns")  # For file-based tools
    
    # Get case directory for progress updates
    case_dir = out_path.parent
    
    # Resolve evidence path (directory or file)
    evidence_path, evidence_desc = resolve_evidence_path(intake_data, evidence_arg)
    
    if not evidence_path or not evidence_path.exists():
        print(f"[INFO] Skipping {tool_id}: evidence not available ({evidence_arg})")
        auto_doc["stages"][tool_id] = "skipped (no evidence)"
        write_progress_update(case_dir, tool_id, "skipped", 0, "Evidence not available")
        write_auto_doc(auto_doc, out_path)
        return auto_doc
    
    # For file-based tools, find specific files
    found_files = []
    if file_patterns:
        found_files, status_msg = find_evidence_files(evidence_path, file_patterns)
        
        if not found_files:
            # Silent skip - files not present, mark as skipped without noisy output
            auto_doc["stages"][tool_id] = "skipped (required files not present)"
            write_progress_update(case_dir, tool_id, "skipped", 0, "Required files not found")
            write_auto_doc(auto_doc, out_path)
            return auto_doc
        
        # Files found - log what we're processing
        if status_msg:
            print(f"[INFO] {tool_id}: {status_msg}")
        
        # For single-file tools, use the first match (typical case)
        # For multi-file tools, we pass all files (tool must handle multiple paths)
        if len(found_files) == 1:
            target_path = found_files[0]
            print(f"[INFO] {tool_id}: Processing single file: {target_path.name}")
        else:
            # Multiple files found - for now process all, but log clearly
            target_path = found_files[0]  # Pipeline receives first file
            print(f"[INFO] {tool_id}: Multiple files found ({len(found_files)}), processing: {target_path.name}")
            # Log additional files for visibility
            for i, f in enumerate(found_files[1:], 2):
                print(f"[INFO] {tool_id}: Additional file {i}: {f.name}")
    else:
        # Directory-based tool (chainsaw, hayabusa, plaso)
        target_path = evidence_path
    
    # Build command
    run_id = f"{intake_id}{run_id_suffix}"
    cmd = [str(script), run_id, ts, str(target_path), intake_id]
    
    # Get file count for progress details
    file_count = len(found_files) if found_files else 1
    
    # Write initial progress
    write_progress_update(case_dir, tool_id, "initializing", 0, 
                          f"Preparing to run {tool_id}",
                          {"evidence": str(target_path), "files_found": file_count})
    
    print(f"[INFO] Running {tool_id} (evidence: {evidence_desc})")
    auto_doc["stages"][tool_id] = "running"
    write_auto_doc(auto_doc, out_path)
    
    # Write running progress
    write_progress_update(case_dir, tool_id, "running", 10, 
                          f"Running {tool_id}...",
                          {"pid": None})  # PID will be updated if we track it
    
    try:
        run_must(cmd)
        auto_doc["stages"][tool_id] = "ok"
        write_progress_update(case_dir, tool_id, "completed", 100, 
                              f"{tool_id} completed successfully")
        print(f"[INFO] {tool_id} completed successfully")
    except SystemExit as e:
        auto_doc["stages"][tool_id] = f"error: {e}"
        write_progress_update(case_dir, tool_id, "error", 0, 
                              f"{tool_id} failed with exit code {e.code}")
        print(f"[WARN] {tool_id} failed with code {e.code}")
    except Exception as e:
        auto_doc["stages"][tool_id] = f"error: {e}"
        write_progress_update(case_dir, tool_id, "error", 0, 
                              f"{tool_id} exception: {str(e)[:100]}")
        print(f"[WARN] {tool_id} exception: {e}")
    
    write_auto_doc(auto_doc, out_path)
    return auto_doc

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def write_auto_doc(auto_doc: dict, out_path: Path):
    """Write auto.json incrementally for real-time progress tracking."""
    out_path.write_text(json.dumps(auto_doc, indent=2), encoding="utf-8")

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
    
    # Tool Selection Enforcement
    ap.add_argument("--selected-tools", type=str,
                    help="Comma-separated list of tools to run (enforces exact tool selection)")

    args = ap.parse_args()

    intake_json = Path(args.intake_json)
    if not intake_json.is_file():
        print(f"FAIL: intake.json not found: {intake_json}", file=sys.stderr)
        return 2

    intake = load_json(intake_json)
    
    # LOAD SELECTED TOOLS: Priority order --selected-tools > intake.json > None
    selected_tools = None
    if args.selected_tools:
        selected_tools = [t.strip() for t in args.selected_tools.split(",") if t.strip()]
        print(f"[INFO] Tool selection from command line: {selected_tools}")
    elif intake.get("selected_tools"):
        selected_tools = intake["selected_tools"]
        print(f"[INFO] Tool selection from intake.json: {selected_tools}")
    else:
        print(f"[WARN] No tool selection specified - will use playbook defaults")
    
    # Helper function to check if a tool should run
    def should_run_tool(tool_id: str) -> bool:
        """Check if tool_id is in selected_tools (if selection is enforced)."""
        if selected_tools is None:
            return True  # No enforcement, allow all
        return tool_id in selected_tools
    
    # Schema Detection (V30 Compatibility)
    if "case_id" in intake:
        intake_id = intake["case_id"]
        # Inferred classification based on evidence
        evidence_types = [e["type"] for e in intake.get("evidence", [])]
        ev_names = [e["name"].lower() for e in intake.get("evidence", [])]
        
        if "windows_triage_dir" in evidence_types:
            kind = "windows_triage_dir"
            rec = "plaso_evtx"
        elif "evtx" in evidence_types or "evtx_dir" in evidence_types:
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
        elif any("destinations-ms" in name.lower() for name in ev_names):
            kind = "windows_jumplist"
            rec = "jlecmd"
        elif any(".dat" in name.lower() or "software" in name.lower() or "security" in name.lower() or "sam" in name.lower() or "default" in name.lower() for name in ev_names):
            kind = "windows_registry"
            rec = "recmd"
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
        if selected_tools:
            dispatch_cmd.extend(["--selected-tools", ",".join(selected_tools)])
        run_must(dispatch_cmd)
        dispatch_json = intake_json.parent / "dispatch.json"
        d = load_json(dispatch_json)
        dispatch_block = {
            "status": "ok" if d["result"]["ok"] else "error",
            "dispatch_json": str(dispatch_json),
            "run_id": d["result"]["run_id"],
            "manifest_path": d["result"]["manifest_path"],
            "steps": d["result"].get("steps", [])  # Include step history for stage tracking
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
            "chainsaw_evtx": "skipped",
            "hayabusa_evtx": "skipped",
            "appcompatcache": "skipped",
            "mftecmd": "skipped",
            "rbcmd": "skipped",
            "lecmd": "skipped",
            "recentfilecache": "skipped",
            "jlecmd": "skipped",
            "recmd": "skipped",
            "enrichment": "skipped",
            "merge": "skipped"
        }
    }
    # 5) Populate dispatch pipeline stages (chainsaw, hayabusa) from step history
    if dispatch_block["status"] == "ok" and "steps" in dispatch_block:
        for step_result in dispatch_block["steps"]:
            # step_result format: "chainsaw_evtx: ok" or "chainsaw_evtx: failed (rc=2)"
            if ": " in step_result:
                parts = step_result.split(": ", 1)
                if len(parts) == 2:
                    pipeline_name, status = parts
                    if pipeline_name in ["chainsaw_evtx", "hayabusa_evtx"]:
                        auto_doc["stages"][pipeline_name] = status
    
    out_path = intake_json.parent / "auto.json"
    write_auto_doc(auto_doc, out_path)  # Initial write for dispatch stage

    # --- Dynamic Tool Runner ---
    # Runs tools based on selection or evidence type
    # This is the plug-and-play approach - adding a tool only requires
    # adding an entry to TOOL_REGISTRY above (no code changes)
    
    tools_to_run = set()
    
    # If tools are explicitly selected, use that list
    if selected_tools:
        tools_to_run.update(selected_tools)
    else:
        # No explicit selection - use evidence-based recommendations
        if rec and dispatch_block["status"] == "ok":
            tools_to_run.add(rec)
    
    # Also include tools from dispatch (playbook steps)
    if dispatch_block["status"] == "ok" and "steps" in dispatch_block:
        for step_result in dispatch_block["steps"]:
            if ": " in step_result:
                parts = step_result.split(": ", 1)
                if len(parts) == 2:
                    tool_name = parts[0]
                    if tool_name in TOOL_REGISTRY:
                        tools_to_run.add(tool_name)
    
    # Run selected tools dynamically
    for tool_id in tools_to_run:
        # Check if tool already completed successfully from dispatch
        # Don't overwrite "ok" status with "skipped"
        current_status = auto_doc["stages"].get(tool_id, "")
        if current_status == "ok" or current_status.startswith("ok "):
            print(f"[INFO] Tool '{tool_id}' already completed successfully, preserving status")
            continue
        
        if not should_run_tool(tool_id):
            print(f"[INFO] Tool '{tool_id}' not in selected tools, skipping")
            # Only mark as skipped if not already completed
            if not (current_status == "ok" or current_status.startswith("ok")):
                auto_doc["stages"][tool_id] = "skipped (not selected)"
            continue
        
        if tool_id not in TOOL_REGISTRY:
            print(f"[WARN] Tool '{tool_id}' not in TOOL_REGISTRY, skipping")
            auto_doc["stages"][tool_id] = "skipped (not registered)"
            continue
        
        # Run tool dynamically
        auto_doc = run_tool_dynamically(
            tool_id=tool_id,
            intake_data=intake,
            intake_id=intake_id,
            ts=ts,
            auto_doc=auto_doc,
            out_path=out_path,
            selected_tools=selected_tools
        )
    
    # Log any tools not run
    for tool_id in TOOL_REGISTRY:
        if tool_id not in tools_to_run:
            auto_doc["stages"].setdefault(tool_id, "skipped (not recommended)")

    # 6) Optional enrichment stage
    if args.enrichment_policy == "always":
        plan_json = intake_json.parent / "enrichment_plan.json"
        enrich_json = intake_json.parent / "enrichment.json"
        auto_doc["stages"]["enrichment"] = "running"
        write_auto_doc(auto_doc, out_path)

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
        write_auto_doc(auto_doc, out_path)

    # 7) Optional merge stage
    if args.run_merge and dispatch_block.get("manifest_path"):
        auto_doc["stages"]["merge"] = "running"
        write_auto_doc(auto_doc, out_path)
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
        write_auto_doc(auto_doc, out_path)
    elif args.run_merge:
        # User requested merge, but we lack a manifest (likely pipeline failure)
        auto_doc["stages"]["merge"] = "skipped (missing baseline manifest)"
        write_auto_doc(auto_doc, out_path)

    # 8) Final write of auto.json (full state)
    write_auto_doc(auto_doc, out_path)
    print(f"OK: wrote {out_path}")

    # 9) Validate auto.json
    run_must([str(VALIDATE_AUTO), str(AUTO_SCHEMA), str(out_path)])

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

