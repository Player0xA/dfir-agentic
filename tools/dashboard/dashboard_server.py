from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import json
import os

app = FastAPI(title="DFIR-Agentic Dashboard API")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

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
                                "name": data.get("case_id", d.name),
                                "classification": data.get("classification", {}),
                                "intake_utc": data.get("intake_utc", "")
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
async def get_findings(case_id: str, severity: str = None):
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
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    if not case_dir.exists():
        return {"artifacts": []}
    
    found_artifacts = []
    
    # Check top level artifacts dir
    artifacts_dir = case_dir / "artifacts"
    if artifacts_dir.exists():
        for item in artifacts_dir.rglob("*"):
            if item.is_file():
                found_artifacts.append({
                    "name": item.name,
                    "relpath": str(item.relative_to(case_dir)),
                    "size": item.stat().st_size
                })
                
    # Check inside orchestrator runs for tool outputs
    orch_dir = case_dir / "orchestrator"
    if orch_dir.exists():
        for run_dir in orch_dir.iterdir():
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                # Sometimes tools drop files directly in run_X or run_X/artifacts
                for item in run_dir.rglob("*"):
                    # Ignore python scripts, standard logs, and hidden files
                    if item.is_file() and not item.name.endswith(".py") and not item.name.endswith(".log") and not item.name.startswith("."):
                        # Only grab actual data outputs like csv, json, sqlite, txt
                        if item.suffix.lower() in [".csv", ".json", ".sqlite", ".db", ".txt", ".plaso", ".toon"]:
                            # Skip the standard orchestrator framework files
                            if item.name not in ["summary.md", "audit_ledger.jsonl", "manifest.json", "plan.md", "progress.md", "request.json"]:
                                found_artifacts.append({
                                    "name": item.name,
                                    "relpath": f"orchestrator/{item.relative_to(orch_dir)}",
                                    "size": item.stat().st_size
                                })
                                
    # Check global output directories for this specific case_id
    global_out_dirs = ["jsonl", "csv", "toon", "html", "plaso"]
    outputs_root = PROJECT_ROOT / "outputs"
    
    for g_dir in global_out_dirs:
        target_dir = outputs_root / g_dir
        if target_dir.exists():
            # Tools often write to outputs/<format>/<tool_name>/<case_id>/
            for tool_dir in target_dir.iterdir():
                if tool_dir.is_dir():
                    case_specific_dir = tool_dir / case_id
                    if case_specific_dir.exists():
                        for item in case_specific_dir.rglob("*"):
                            if item.is_file() and not item.name.startswith("."):
                                # Skip noisy framework files
                                if item.name not in ["request.json", "stdout.log", "stderr.log"]:
                                    found_artifacts.append({
                                        "name": item.name,
                                        "relpath": f"outputs/{g_dir}/{tool_dir.name}/{case_id}/{item.relative_to(case_specific_dir)}",
                                        "size": item.stat().st_size
                                    })
                                    
    return {"artifacts": found_artifacts}

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

def run_server(host="0.0.0.0", port=8080):
    import uvicorn
    print(f"Starting DFIR-Agentic Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
