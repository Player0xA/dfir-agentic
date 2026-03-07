from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import json
import os
import subprocess
import shutil
from datetime import datetime

app = FastAPI(title="DFIR-Agentic Dashboard API")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Available tools configuration
AVAILABLE_TOOLS = {
    "chainsaw_evtx": {
        "name": "Chainsaw EVTX",
        "description": "Fast Sigma-based detection for Windows Event Logs",
        "evidence_types": ["windows_evtx_dir", "windows_triage_dir", "windows_evtx_file"],
        "speed": "fast",
        "default": True
    },
    "hayabusa_evtx": {
        "name": "Hayabusa EVTX", 
        "description": "High-speed threat hunting for Windows Event Logs",
        "evidence_types": ["windows_evtx_dir", "windows_triage_dir", "windows_evtx_file"],
        "speed": "medium",
        "default": True,
        "tiers": ["quick", "deep"]
    },
    "plaso_evtx": {
        "name": "Plaso Super Timeline",
        "description": "Comprehensive timeline generation from all evidence",
        "evidence_types": ["windows_triage_dir", "disk_image_file"],
        "speed": "slow",
        "default": True
    },
    "mem_forensics": {
        "name": "Memory Analysis",
        "description": "Volatility 3 memory forensics analysis",
        "evidence_types": ["memory_dump_file"],
        "speed": "medium",
        "default": True
    },
    "recmd": {
        "name": "Registry Analysis",
        "description": "Parse Windows registry hives with RECmd",
        "evidence_types": ["windows_triage_dir"],
        "speed": "fast",
        "default": False
    },
    "mftecmd": {
        "name": "MFT Analysis",
        "description": "Parse Master File Table with MFTECmd",
        "evidence_types": ["windows_triage_dir"],
        "speed": "fast", 
        "default": False
    },
    "rbcmd": {
        "name": "Recycle Bin Analysis",
        "description": "Parse Recycle Bin artifacts",
        "evidence_types": ["windows_triage_dir"],
        "speed": "fast",
        "default": False
    }
}

# Serve static files from the static directory
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

def get_intake_dir():
    # If the environment variable isn't set, try reading from cases by default
    case_dir = os.environ.get("DFIR_CASE_DIR")
    if case_dir:
        return Path(case_dir)
    return PROJECT_ROOT / "outputs" / "intake"

@app.get("/", response_class=HTMLResponse)
async def read_root():
    index_path = static_dir / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>DFIR-Agentic Dashboard</h1><p>Static files not found.</p>"

@app.get("/api/cases")
async def list_cases():
    """List all available cases in outputs/intake/."""
    try:
        cases = []
        intake_root = PROJECT_ROOT / "outputs" / "intake"
        if not intake_root.exists():
            return {"cases": []}
            
        for d in intake_root.iterdir():
            if d.is_dir():
                intake_json_path = d / "intake.json"
                if intake_json_path.exists():
                    try:
                        with open(intake_json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            cases.append({
                                "id": d.name,
                                "name": data.get("display_name") or data.get("case_name") or d.name,
                                "case_name": data.get("case_name"),
                                "display_name": data.get("display_name"),
                                "classification": data.get("classification", {}),
                                "intake_utc": data.get("timestamp_utc", "")
                            })
                    except json.JSONDecodeError:
                        continue
        return {"cases": sorted(cases, key=lambda x: x["intake_utc"], reverse=True)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    """Get metadata for a specific case."""
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    if not case_dir.exists():
        raise HTTPException(status_code=404, detail="Case not found")
        
    intake_json_path = case_dir / "intake.json"
    manifest_json_path = case_dir / "case_manifest.json"
    
    result = {"id": case_id, "intake": {}, "manifest": {}, "is_active": True}
    
    if intake_json_path.exists():
        try:
            with open(intake_json_path, "r", encoding="utf-8") as f:
                result["intake"] = json.load(f)
        except Exception: pass
        
    if manifest_json_path.exists():
        try:
            with open(manifest_json_path, "r", encoding="utf-8") as f:
                result["manifest"] = json.load(f)
        except Exception: pass
        
    # Check if the orchestrator has finished by looking for summary.md in any of its run dirs
    orchestrator_dir = case_dir / "orchestrator"
    if orchestrator_dir.exists():
        for run_dir in orchestrator_dir.iterdir():
            if run_dir.is_dir() and (run_dir / "summary.md").exists():
                result["is_active"] = False
                break
                
    return result

@app.get("/api/cases/{case_id}/findings")
async def get_findings(case_id: str, severity: str | None = None):
    """Get findings for a case, optionally filtered by severity."""
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    findings_path = case_dir / "case_findings.json"
    
    if not findings_path.exists():
        return {"findings": []}
        
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            findings = data.get("findings", [])
            
            if severity:
                findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
                
            return {"findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load findings: {str(e)}")

@app.get("/api/cases/{case_id}/notes")
async def get_notes(case_id: str):
    """Get markdown notes for a case."""
    # Find the actively written progress.md
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    progress_path = case_dir / "progress.md"
    
    if not progress_path.exists():
        return {"notes": "*No progress notes found.*"}
        
    try:
        with open(progress_path, "r", encoding="utf-8") as f:
            content = f.read()
            return {"notes": content if content.strip() else "*No progress notes found.*"}
    except Exception as e:
        return {"notes": f"Error loading notes: {str(e)}"}

@app.get("/api/cases/{case_id}/generated_artifacts")
async def get_generated_artifacts(case_id: str):
    """Scan the case directory for any tool-generated artifacts (CSVs, JSONs, etc)."""
    import json
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    if not case_dir.exists():
        return {"artifacts": []}
    
    found_artifacts = []
    
    def scan_dir(d, prefix=""):
        if d.exists():
            for item in d.rglob("*"):
                if item.is_file() and not item.name.startswith(".") and not item.name.endswith(".py") and not item.name.endswith(".log"):
                    if item.suffix.lower() in [".csv", ".json", ".sqlite", ".txt", ".plaso", ".jsonl", ".db"]:
                        found_artifacts.append({
                            "name": item.name,
                            "relpath": f"{prefix}{item.name}",
                            "size": item.stat().st_size
                        })

    # 1. Check top level artifacts dir
    scan_dir(case_dir / "artifacts", "artifacts/")
    
    # 2. Check orchestrator
    orch_dir = case_dir / "orchestrator"
    if orch_dir.exists():
        for run_dir in orch_dir.iterdir():
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                scan_dir(run_dir, f"orchestrator/{run_dir.name}/")
                
    # 3. Check Plaso
    plaso_file = case_dir / f"{case_id}.plaso"
    if plaso_file.exists():
        found_artifacts.append({
            "name": plaso_file.name,
            "relpath": f"supertimeline/{plaso_file.name}",
            "size": plaso_file.stat().st_size
        })

    # 4. Check auto.json (Chainsaw baseline)
    auto_json = case_dir / "auto.json"
    if auto_json.exists():
        try:
            with open(auto_json, "r") as f:
                auto_data = json.load(f)
            baseline_run_id = auto_data.get("dispatch", {}).get("run_id")
            if baseline_run_id:
                scan_dir(PROJECT_ROOT / "outputs" / "jsonl" / "chainsaw_evtx" / baseline_run_id, "chainsaw/")
                scan_dir(PROJECT_ROOT / "outputs" / "csv" / "chainsaw_evtx" / baseline_run_id, "chainsaw/")
        except Exception:
            pass

    # 5. Check enrichment.json (Hayabusa enrichment)
    enrich_json = case_dir / "enrichment.json"
    if enrich_json.exists():
        try:
            with open(enrich_json, "r") as f:
                enrich_data = json.load(f)
            enrich_run_id = enrich_data.get("result", {}).get("run_id")
            if enrich_run_id:
                scan_dir(PROJECT_ROOT / "outputs" / "jsonl" / "hayabusa_evtx" / enrich_run_id, "hayabusa/")
                scan_dir(PROJECT_ROOT / "outputs" / "csv" / "hayabusa_evtx" / enrich_run_id, "hayabusa/")
        except Exception:
            pass
            
    # Remove duplicates if any
    unique_artifacts = {a["relpath"]: a for a in found_artifacts}.values()

    return {"artifacts": list(unique_artifacts)}


@app.get("/api/cases/{case_id}/audit")
async def get_audit(case_id: str):
    """Get the audit ledger for the most recent run."""
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id / "orchestrator"
    if not case_dir.exists():
        return {"audit": []}
        
    try:
        latest_file = None
        latest_time = 0
        
        for run_dir in case_dir.iterdir():
            if run_dir.is_dir():
                audit_path = run_dir / "audit_ledger.jsonl"
                if audit_path.exists():
                    mtime = audit_path.stat().st_mtime
                    if mtime > latest_time:
                        latest_time = mtime
                        latest_file = audit_path
                        
        audit_entries = []
        if latest_file:
            with open(latest_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            audit_entries.append(json.loads(line))
                        except Exception: pass
        return {"audit": audit_entries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cases/{case_id}/logs")
async def get_case_logs(case_id: str, lines: int = 50):
    """Get investigation log file for a case."""
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        log_file = case_dir / "investigation.log"
        
        if not log_file.exists():
            return {"logs": []}
        
        # Read last N lines from log file
        logs = []
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
            logs = [line.rstrip() for line in all_lines[-lines:]]
        
        return {"logs": logs}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")

# Layout persistence endpoints
SETTINGS_FILE = Path.home() / ".dfir-agentic" / "dashboard_prefs.json"

@app.get("/api/settings")
async def get_settings():
    if not SETTINGS_FILE.parent.exists():
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    default_settings = {
        "active_profile": "Default",
        "profiles": {
            "Default": [] # Empty list tells frontend to use its hardcoded default layout
        }
    }
    
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
                # Handle legacy format (flat array)
                if isinstance(data, list):
                    return {
                        "active_profile": "Default",
                        "profiles": {
                            "Default": data
                        }
                    }
                return data
        except Exception:
            return default_settings
    return default_settings

@app.post("/api/settings")
async def save_settings(payload: dict):
    if not SETTINGS_FILE.parent.exists():
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        
    # Ensure structure is valid
    if "active_profile" not in payload or "profiles" not in payload:
        raise HTTPException(status_code=400, detail="Invalid payload structure. Expected active_profile and profiles dict.")
        
    with open(SETTINGS_FILE, "w") as f:
        json.dump(payload, f, indent=2)
    
    return {"status": "success"}

@app.get("/api/tools")
async def list_tools():
    """List all available forensic tools with their descriptions."""
    return {"tools": AVAILABLE_TOOLS}

@app.get("/api/tools/recommended")
async def get_recommended_tools(evidence_type: str):
    """Get recommended tools for a specific evidence type."""
    recommended = {}
    for tool_id, tool_info in AVAILABLE_TOOLS.items():
        if evidence_type in tool_info.get("evidence_types", []):
            recommended[tool_id] = tool_info
    return {"tools": recommended, "evidence_type": evidence_type}

@app.post("/api/intake")
async def create_intake(
    paths: str = Form(...),  # Comma-separated paths
    case_name: str = Form(None),
    display_name: str = Form(None)
):
    """Create a new intake from evidence paths with friendly naming."""
    try:
        # Parse paths
        path_list = [p.strip() for p in paths.split(",") if p.strip()]
        if not path_list:
            raise HTTPException(status_code=400, detail="No valid paths provided")
        
        # Run identify_evidence.py
        cmd = [
            "python3", 
            str(PROJECT_ROOT / "tools" / "intake" / "identify_evidence.py"),
            *path_list,
            "--out-base", str(PROJECT_ROOT / "outputs" / "intake")
        ]
        
        if case_name:
            cmd.extend(["--case-name", case_name])
        if display_name:
            cmd.extend(["--display-name", display_name])
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Intake failed: {result.stderr}")
            
        # Parse the output to get the case directory
        output_lines = result.stdout.strip().split('\n')
        intake_json_path = None
        for line in output_lines:
            if "wrote" in line:
                # Extract path from "OK: wrote /path/to/intake.json"
                intake_json_path = line.split("wrote ")[1].strip()
                break
                
        if not intake_json_path:
            raise HTTPException(status_code=500, detail="Could not determine intake location")
            
        # Load the intake.json to get case info
        intake_path = Path(intake_json_path)
        with open(intake_path, "r") as f:
            intake_data = json.load(f)
            
        return {
            "success": True,
            "case_name": intake_data.get("case_name"),
            "display_name": intake_data.get("display_name"),
            "intake_id": intake_data.get("intake_id"),
            "classification": intake_data.get("classification"),
            "paths": path_list
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/classify")
async def classify_evidence(paths: str = Form(...)):
    """Classify evidence paths without creating a case."""
    try:
        path_list = [p.strip() for p in paths.split(",") if p.strip()]
        if not path_list:
            raise HTTPException(status_code=400, detail="No valid paths provided")
        
        # Run identify_evidence.py in classify-only mode
        cmd = [
            "python3",
            str(PROJECT_ROOT / "tools" / "intake" / "identify_evidence.py"),
            "--classify-only",
            *path_list
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Classification failed: {result.stderr}")
        
        # Parse the JSON output
        classification = json.loads(result.stdout)
        return {"success": True, "classification": classification}
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Classification timed out")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse classification result")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate")
async def create_and_start_investigation(
    paths: str = Form(...),  # Comma-separated evidence paths
    case_name: str = Form(None),  # Optional friendly case name
    display_name: str = Form(None),  # Optional display name
    tools: str = Form("")  # Comma-separated tool IDs (optional)
):
    """
    Combined endpoint: create intake AND start investigation in one call.
    This is optimized for fast UI - user clicks start, wizard closes immediately.
    """
    try:
        path_list = [p.strip() for p in paths.split(",") if p.strip()]
        if not path_list:
            raise HTTPException(status_code=400, detail="No valid paths provided")
        
        tool_list = [t.strip() for t in tools.split(",") if t.strip()] if tools else []
        
        # Step 1: Create intake
        cmd = [
            "python3",
            str(PROJECT_ROOT / "tools" / "intake" / "identify_evidence.py"),
            *path_list,
            "--out-base", str(PROJECT_ROOT / "outputs" / "intake")
        ]
        
        if case_name:
            cmd.extend(["--case-name", case_name])
        if display_name:
            cmd.extend(["--display-name", display_name])
            
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Intake failed: {result.stderr}")
            
        # Parse the output to get the case directory
        output_lines = result.stdout.strip().split('\n')
        intake_json_path = None
        for line in output_lines:
            if "wrote" in line:
                intake_json_path = line.split("wrote ")[1].strip()
                break
                
        if not intake_json_path:
            raise HTTPException(status_code=500, detail="Could not determine intake location")
            
        # Load the intake.json to get case info
        intake_path = Path(intake_json_path)
        with open(intake_path, "r") as f:
            intake_data = json.load(f)
        
        actual_case_name = intake_data.get("case_name")
        case_dir = PROJECT_ROOT / "outputs" / "intake" / actual_case_name
        
        # Step 2: Start investigation in background (if tools specified)
        investigation_pid = None
        if tool_list:
            # Get evidence path from intake
            evidence_path = intake_data.get("inputs", {}).get("paths", [None])[0]
            
            if evidence_path:
                # Create initial status
                status_file = case_dir / "investigation_status.json"
                status = {
                    "status": "starting",
                    "started_at": datetime.now().isoformat(),
                    "tools": tool_list,
                    "completed_tools": [],
                    "current_tool": "initializing",
                    "current_action": "Starting investigation...",
                    "progress": 0,
                    "logs": [],
                    "pid": None
                }
                
                with open(status_file, "w") as f:
                    json.dump(status, f, indent=2)
                
                # Run dfir.py in background
                dfir_script = PROJECT_ROOT / "dfir.py"
                cmd = ["python3", str(dfir_script), evidence_path]
                
                env = os.environ.copy()
                env["DFIR_CASE_NAME"] = actual_case_name
                
                # Open log file for verbose output (prevents pipe deadlock)
                log_file_path = case_dir / "investigation.log"
                log_file = open(log_file_path, "w")
                
                process = subprocess.Popen(
                    cmd,
                    cwd=str(PROJECT_ROOT),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=True
                )
                
                investigation_pid = process.pid
                status["pid"] = investigation_pid
                status["current_action"] = f"Running (PID: {process.pid})..."
                status["logs"].append(f"[{datetime.now().isoformat()}] Investigation started")
                status["log_file"] = str(log_file_path)
                
                with open(status_file, "w") as f:
                    json.dump(status, f, indent=2)
        
        # Return immediately - UI can update
        return {
            "success": True,
            "case_name": actual_case_name,
            "display_name": intake_data.get("display_name"),
            "intake_id": intake_data.get("intake_id"),
            "classification": intake_data.get("classification"),
            "paths": path_list,
            "investigation_started": bool(tool_list),
            "investigation_pid": investigation_pid,
            "message": "Investigation started" if tool_list else "Case created"
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Operation timed out")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate/start")
async def start_investigation(
    case_name: str = Form(...),
    tools: str = Form(...),  # Comma-separated tool IDs
    options: str = Form("{}")  # JSON string of options
):
    """Start an investigation with selected tools in background."""
    try:
        tool_list = [t.strip() for t in tools.split(",") if t.strip()]
        options_dict = json.loads(options)
        
        # Check if case exists
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_name
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_name}' not found")
        
        # Get evidence path from intake.json
        intake_json = case_dir / "intake.json"
        evidence_path = None
        if intake_json.exists():
            with open(intake_json, "r") as f:
                intake_data = json.load(f)
                evidence_path = intake_data.get("inputs", {}).get("paths", [None])[0]
        
        if not evidence_path:
            raise HTTPException(status_code=400, detail="No evidence path found in case")
        
        # Create investigation status file
        status_file = case_dir / "investigation_status.json"
        status = {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "tools": tool_list,
            "completed_tools": [],
            "current_tool": "initializing",
            "current_action": "Starting investigation...",
            "progress": 0,
            "logs": [],
            "pid": None
        }
        
        with open(status_file, "w") as f:
            json.dump(status, f, indent=2)
        
        # Run the dfir.py pipeline in background using subprocess.Popen
        # This will run auto_run.py which runs all the selected tools
        dfir_script = PROJECT_ROOT / "dfir.py"
        
        # Build command - dfir.py takes evidence path as argument
        # It will automatically run the appropriate tools based on evidence type
        cmd = [
            "python3",
            str(dfir_script),
            evidence_path
        ]
        
        # Set environment to track this run
        env = os.environ.copy()
        env["DFIR_CASE_NAME"] = case_name
        
        # Open log file for verbose output (prevents pipe deadlock)
        log_file_path = case_dir / "investigation.log"
        log_file = open(log_file_path, "w")
        
        # Start process in background - don't wait for completion
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True  # Detach from parent process
        )
        
        # Update status with PID
        status["pid"] = process.pid
        status["current_action"] = f"Running dfir.py (PID: {process.pid})..."
        status["logs"].append(f"[{datetime.now().isoformat()}] Starting investigation with {len(tool_list)} tools")
        status["logs"].append(f"[{datetime.now().isoformat()}] Evidence path: {evidence_path}")
        status["log_file"] = str(log_file_path)
        
        with open(status_file, "w") as f:
            json.dump(status, f, indent=2)
        
        return {
            "success": True,
            "case_name": case_name,
            "evidence_path": evidence_path,
            "tools_selected": tool_list,
            "status": "started",
            "pid": process.pid,
            "message": "Investigation started in background."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/investigate/status/{case_name}")
async def get_investigation_status(case_name: str):
    """Get verbose status of an investigation by reading pipeline logs."""
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_name
        status_file = case_dir / "investigation_status.json"
        
        # Check if case directory exists
        if not case_dir.exists():
            return {"status": "not_found", "case_name": case_name}
        
        # Check if completed (has summary.md in orchestrator)
        orchestrator_dir = case_dir / "orchestrator"
        if orchestrator_dir.exists():
            for run_dir in orchestrator_dir.iterdir():
                if run_dir.is_dir() and (run_dir / "summary.md").exists():
                    return {
                        "status": "completed",
                        "case_name": case_name,
                        "has_summary": True,
                        "progress": 100,
                        "current_tool": "completed",
                        "current_action": "Investigation complete"
                    }
        
        # Check if there's an auto.json with stage status (from auto_run.py)
        auto_json_path = case_dir / "auto.json"
        stage_info = {}
        if auto_json_path.exists():
            try:
                with open(auto_json_path, "r") as f:
                    auto_data = json.load(f)
                    stage_info = auto_data.get("stages", {})
            except Exception:
                pass
        
        # If we have stage info, determine current progress
        if stage_info:
            completed = []
            running = None
            pending = []
            
            # Stage name mapping: auto_run.py stage names → display names
            # auto_run.py creates stages: plaso, appcompatcache, mftecmd, rbcmd, lecmd, 
            # recentfilecache, jlecmd, recmd, enrichment, merge
            stage_display_map = {
                "plaso": "Plaso Super Timeline",
                "chainsaw_evtx": "Chainsaw EVTX Analysis",
                "hayabusa_evtx": "Hayabusa Threat Hunting",
                "appcompatcache": "AppCompatCache Parser",
                "mftecmd": "MFT Analysis",
                "rbcmd": "Recycle Bin Analysis",
                "lecmd": "LNK File Analysis",
                "recentfilecache": "RecentFileCache Parser",
                "jlecmd": "Jump List Analysis",
                "recmd": "Registry Analysis",
                "enrichment": "Hayabusa Enrichment",
                "merge": "Data Aggregation"
            }
            
            # Tool order based on what auto_run.py actually creates
            # Dispatch pipelines (chainsaw, hayabusa) run first, then direct runners
            tool_order = ["chainsaw_evtx", "hayabusa_evtx", "plaso", "appcompatcache", "mftecmd", "rbcmd", 
                         "lecmd", "recentfilecache", "jlecmd", "recmd", 
                         "enrichment", "merge"]
            
            for tool in tool_order:
                if tool in stage_info:
                    status = stage_info[tool]
                    display_name = stage_display_map.get(tool, tool)
                    if status == "ok":
                        completed.append(display_name)
                    elif status == "running":
                        running = display_name
                    elif status == "skipped":
                        pass  # Skip skipped tools
                    else:
                        pending.append(display_name)
            
            # Build verbose current action
            current_action = "Initializing..."
            if running:
                current_action = f"Running {running}..."
            elif completed:
                last_tool = completed[-1]
                # Add context based on the tool
                if "Plaso" in last_tool:
                    current_action = "Plaso timeline generation complete. Starting next analysis..."
                elif "Hayabusa" in last_tool:
                    current_action = "Hayabusa threat hunting complete. Correlating findings..."
                elif "MFT" in last_tool:
                    current_action = "MFT analysis complete."
                elif "Registry" in last_tool:
                    current_action = "Registry analysis complete."
                else:
                    current_action = f"{last_tool} complete."
            
            progress = int((len(completed) / max(len(completed) + len(pending) + (1 if running else 0), 1)) * 100)
            
            # Check if process is still running
            pid = None
            if status_file.exists():
                try:
                    with open(status_file, "r") as f:
                        status_data = json.load(f)
                        pid = status_data.get("pid")
                except Exception:
                    pass
            
            # Check if process is dead
            process_running = False
            if pid:
                try:
                    import signal
                    os.kill(pid, 0)  # Signal 0 just checks if process exists
                    process_running = True
                except (OSError, ProcessLookupError):
                    process_running = False
            
            # If process is not running but no summary yet, it might have failed
            if not process_running and not completed and not (orchestrator_dir and any((orchestrator_dir / d).is_dir() for d in os.listdir(orchestrator_dir))):
                return {
                    "status": "error",
                    "case_name": case_name,
                    "error": "Investigation process ended unexpectedly",
                    "progress": 0
                }
            
            return {
                "status": "running",
                "case_name": case_name,
                "progress": progress,
                "current_tool": running or "unknown",
                "current_action": current_action,
                "completed_tools": completed,
                "pending_tools": pending,
                "stages": stage_info,
                "pid": pid,
                "process_running": process_running,
                "log_file": str(case_dir / "investigation.log") if (case_dir / "investigation.log").exists() else None
            }
        
        # If no auto.json yet, check if investigation_status.json exists
        if status_file.exists():
            with open(status_file, "r") as f:
                status = json.load(f)
                # Check if process is still running
                pid = status.get("pid")
                if pid:
                    try:
                        os.kill(pid, 0)
                    except (OSError, ProcessLookupError):
                        status["process_running"] = False
                # Add log file path if it exists
                log_file = case_dir / "investigation.log"
                if log_file.exists():
                    status["log_file"] = str(log_file)
                return status
        
        # No status files - not started
        return {
            "status": "not_started",
            "case_name": case_name
        }
        
    except Exception as e:
        return {"status": "error", "case_name": case_name, "error": str(e)}

@app.get("/api/investigate/summary/{case_name}")
async def get_investigation_summary(case_name: str):
    """Get the AI summary for a completed investigation."""
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_name
        
        # Look for summary.md in orchestrator runs
        orchestrator_dir = case_dir / "orchestrator"
        summary_content = None
        
        if orchestrator_dir.exists():
            for run_dir in orchestrator_dir.iterdir():
                if run_dir.is_dir():
                    summary_path = run_dir / "summary.md"
                    if summary_path.exists():
                        with open(summary_path, "r") as f:
                            summary_content = f.read()
                        break
                        
        if not summary_content:
            return {
                "status": "not_available",
                "case_name": case_name,
                "summary": None
            }
            
        return {
            "status": "available",
            "case_name": case_name,
            "summary": summary_content
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_server(host="0.0.0.0", port=8080):
    import uvicorn
    print(f"Starting DFIR-Agentic Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_server()
