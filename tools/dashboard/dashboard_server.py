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
    
    result = {"id": case_id, "intake": {}, "manifest": {}}
    
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
    # Find the most recent progress.md
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id / "orchestrator"
    if not case_dir.exists():
        return {"notes": ""}
        
    try:
        latest_file = None
        latest_time = 0
        
        # In the orchestrator dir, there are UUID subdirs for each run
        for run_dir in case_dir.iterdir():
            if run_dir.is_dir():
                notes_path = run_dir / "progress.md"
                if notes_path.exists():
                    mtime = notes_path.stat().st_mtime
                    if mtime > latest_time:
                        latest_time = mtime
                        latest_file = notes_path
                        
        if latest_file:
            with open(latest_file, "r", encoding="utf-8") as f:
                return {"notes": f.read()}
        return {"notes": "*No progress notes found.*"}
    except Exception as e:
        return {"notes": f"Error loading notes: {str(e)}"}

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
    
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

@app.post("/api/settings")
async def save_settings(payload: list[dict]):
    if not SETTINGS_FILE.parent.exists():
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        
    with open(SETTINGS_FILE, "w") as f:
        json.dump(payload, f)
    
    return {"status": "success"}

def run_server(host="0.0.0.0", port=8080):
    import uvicorn
    print(f"Starting DFIR-Agentic Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
