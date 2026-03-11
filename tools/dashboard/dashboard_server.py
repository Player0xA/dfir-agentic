#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import json
import os
import subprocess
import shutil
from datetime import datetime, timezone
import time
import hashlib
import logging
import sys

app = FastAPI(title="DFIR-Agentic Dashboard API")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Configure logging for production debugging
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOGS_DIR / "dashboard.log")
    ]
)
logger = logging.getLogger("dashboard")

# Config paths
CONFIG_FILE = PROJECT_ROOT / "config" / "drop_folder.json"

def load_drop_folder_config():
    """Load drop folder configuration from config file."""
    default_config = {
        "drop_folder": os.environ.get("DFIR_EVIDENCE_DROP", "/home/nevermore/evidence_drop"),
        "auto_create": True,
        "scan_on_startup": False,
        "max_display_items": 50
    }
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                # Merge with defaults
                default_config.update(config)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    return default_config

def get_drop_folder():
    """Get the configured drop folder path."""
    config = load_drop_folder_config()
    return Path(config["drop_folder"])

def ensure_drop_folder():
    """Ensure drop folder exists, create if configured."""
    config = load_drop_folder_config()
    drop_folder = Path(config["drop_folder"])
    
    if config.get("auto_create", True):
        drop_folder.mkdir(parents=True, exist_ok=True)
    
    return drop_folder

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
    
    result = {"id": case_id, "intake": {}, "manifest": {}, "is_active": True, "auto_stages": {}}
    
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

    # Load auto.json stages so frontend knows which tools already ran
    auto_json_path = case_dir / "auto.json"
    if auto_json_path.exists():
        try:
            with open(auto_json_path, "r", encoding="utf-8") as f:
                auto_data = json.load(f)
                result["auto_stages"] = auto_data.get("stages", {})
        except Exception: pass
        
    # Check if the orchestrator has finished by looking for summary.md in any of its run dirs
    orchestrator_dir = case_dir / "orchestrator"
    if orchestrator_dir.exists():
        for run_dir in orchestrator_dir.iterdir():
            if run_dir.is_dir() and (run_dir / "summary.md").exists():
                result["is_active"] = False
                break
                
    return result

@app.get("/api/cases/{case_id}/evidence_files")
async def get_evidence_files(case_id: str):
    """List all files within the evidence directories."""
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    if not case_dir.exists():
        return {"files": []}
        
    intake_json = case_dir / "intake.json"
    if not intake_json.exists():
        return {"files": []}
        
    try:
        with open(intake_json, "r") as f:
            intake_data = json.load(f)
            paths = intake_data.get("inputs", {}).get("paths", [])
            
        evidence_files = []
        MAX_FILES = 2000  # Limit to prevent UI freezing
        
        for p in paths:
            path = Path(p)
            if not path.exists():
                continue
                
            if path.is_file():
                evidence_files.append({
                    "name": path.name,
                    "path": str(path),
                    "relpath": path.name,
                    "size": path.stat().st_size,
                    "type": "file"
                })
            elif path.is_dir():
                # BFS to list files
                queue = [path]
                # We need a root for relative path calculation
                # If multiple roots, just use the parent of the current root
                root_parent = path.parent
                
                processed_count = 0
                while queue and processed_count < MAX_FILES:
                    current_dir = queue.pop(0)
                    try:
                        # Sort for deterministic output
                        entries = sorted(list(current_dir.iterdir()), key=lambda x: x.name)
                        for item in entries:
                            if item.is_file():
                                if item.name.startswith("."): continue
                                try:
                                    relpath = str(item.relative_to(root_parent))
                                except ValueError:
                                    relpath = item.name
                                    
                                evidence_files.append({
                                    "name": item.name,
                                    "path": str(item),
                                    "relpath": relpath,
                                    "size": item.stat().st_size,
                                    "type": "file"
                                })
                                processed_count += 1
                                if processed_count >= MAX_FILES:
                                    break
                            elif item.is_dir():
                                if not item.name.startswith("."):
                                    queue.append(item)
                    except PermissionError:
                        pass
                        
        return {"files": evidence_files}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cases/{case_id}/findings")
async def get_findings(case_id: str, severity: str | None = None):
    """Get findings for a case, including live results from tools that have finished."""
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    findings_path = case_dir / "case_findings.json"
    
    findings = []
    
    # First, try to load consolidated findings
    if findings_path.exists():
        try:
            with open(findings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
        except Exception:
            pass
    
    # If no consolidated findings yet, look for live tool outputs
    if not findings:
        # Check for Chainsaw raw findings
        chainsaw_findings = await _load_chainsaw_findings(case_id)
        findings.extend(chainsaw_findings)
        
        # Check for Hayabusa raw findings
        hayabusa_findings = await _load_hayabusa_findings(case_id)
        findings.extend(hayabusa_findings)
        
    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
                
    return {"findings": findings}

async def _load_tool_findings_by_case_id(case_id: str, tool_name: str, jsonl_subdir: str):
    """Load findings from any tool by matching the case's intake_id with the run's case_id.
    
    This is the production-grade, scalable approach that works across:
    - All operating systems (Windows, Linux, macOS, Android)
    - All evidence types (EVTX, registry, MFT, memory dumps, etc.)
    - Multiple evidence sources per investigation
    
    The dashboard uses directory names for clean URLs (e.g., "c-investigation-20260309"),
    but tool runs store the UUID intake_id for reliable matching. This function resolves
    the directory name to the intake_id for proper matching.
    
    Args:
        case_id: The case directory name (used in URLs)
        tool_name: The tool identifier (e.g., "hayabusa", "chainsaw")
        jsonl_subdir: The subdirectory under outputs/jsonl/ (e.g., "hayabusa_evtx")
    
    Returns:
        List of findings from all runs matching the case's intake_id
    """
    findings = []
    
    # Resolve the directory name to the UUID intake_id for matching
    case_intake_json = PROJECT_ROOT / "outputs" / "intake" / case_id / "intake.json"
    target_intake_id = None
    
    if case_intake_json.exists():
        try:
            with open(case_intake_json, "r") as f:
                intake_data = json.load(f)
                target_intake_id = intake_data.get("intake_id") or intake_data.get("case_id")
        except:
            pass
    
    if not target_intake_id:
        return findings
    
    # Look for tool output directories
    tool_base = PROJECT_ROOT / "outputs" / "jsonl" / jsonl_subdir
    if not tool_base.exists():
        return findings
    
    for run_dir in tool_base.iterdir():
        if not run_dir.is_dir():
            continue
        
        request_json = run_dir / "request.json"
        if not request_json.exists():
            continue
        
        # MATCH BY INTAKE_ID (reliable UUID matching)
        try:
            with open(request_json, "r") as f:
                req_data = json.load(f)
                run_case_id = req_data.get("case_id")
                
                # Skip if no case_id or doesn't match the target intake_id
                if not run_case_id or run_case_id != target_intake_id:
                    continue
        except:
            continue
        
        # First try to load findings.json (preferred format)
        findings_json = run_dir / "findings.json"
        if findings_json.exists():
            try:
                with open(findings_json, "r") as f:
                    data = json.load(f)
                    tool_findings = data.get("findings", [])
                    for finding in tool_findings:
                        if not finding.get("source"):
                            finding["source"] = {"tool": tool_name, "rule_title": finding.get("rule_title", f"{tool_name} detection")}
                        finding["_run_id"] = run_dir.name
                        finding["_is_live"] = True
                    findings.extend(tool_findings)
                    continue
            except:
                pass
        
        # Tool-specific raw output parsing (fallback)
        if tool_name == "chainsaw":
            findings.extend(_parse_chainsaw_raw_output(run_dir))
        elif tool_name == "hayabusa":
            findings.extend(_parse_hayabusa_raw_output(run_dir))
    
    return findings

def _parse_chainsaw_raw_output(run_dir: Path):
    """Parse raw chainsaw.evtx.jsonl output when findings.json is not available."""
    findings = []
    output_jsonl = run_dir / "chainsaw.evtx.jsonl"
    
    if not output_jsonl.exists():
        return findings
    
    try:
        with open(output_jsonl, "r") as f:
            idx = 0
            for line in f:
                idx += 1
                try:
                    rec = json.loads(line.strip())
                    if not rec:
                        continue
                    
                    # Extract severity
                    level = rec.get("level", "medium")
                    if level == "info":
                        severity = "informational"
                    else:
                        severity = level.lower()
                    
                    finding = {
                        "finding_id": f"F-CHAINSAW-{run_dir.name[:8]}-{idx:06d}",
                        "category": rec.get("group", rec.get("kind", "unknown")),
                        "summary": rec.get("name", rec.get("title", rec.get("rule", "Detection"))),
                        "severity": severity,
                        "source": {
                            "tool": "chainsaw",
                            "rule_title": rec.get("name", rec.get("title", "Unknown rule"))
                        },
                        "evidence": {
                            "event_refs": [rec.get("event_id", "")],
                            "artifacts": [rec.get("document", {}).get("kind", "")],
                            "raw": rec
                        },
                        "_run_id": run_dir.name,
                        "_is_live": True
                    }
                    findings.append(finding)
                except:
                    continue
    except Exception as e:
        print(f"Error parsing chainsaw jsonl: {e}")
    
    return findings

def _parse_hayabusa_raw_output(run_dir: Path):
    """Parse raw Hayabusa CSV output when findings.json is not available."""
    findings = []
    csv_files = []
    
    # Check for CSV files in jsonl output dir or CSV output dir
    for csv_file in run_dir.iterdir():
        if csv_file.suffix == ".csv":
            csv_files.append(csv_file)
    
    # Also check CSV output directory
    csv_run_dir = PROJECT_ROOT / "outputs" / "csv" / "hayabusa_evtx" / run_dir.name
    if csv_run_dir.exists():
        for csv_file in csv_run_dir.iterdir():
            if csv_file.suffix == ".csv":
                csv_files.append(csv_file)
    
    # Parse CSV files
    for csv_file in csv_files:
        try:
            import csv
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                idx = 0
                for row in reader:
                    idx += 1
                    if not row:
                        continue
                    
                    severity = (row.get("Level", "medium") or "medium").lower()
                    if severity == "info":
                        severity = "informational"
                    
                    finding = {
                        "finding_id": f"F-HAYA-{run_dir.name[:8]}-{idx:06d}",
                        "timestamp": row.get("Timestamp"),
                        "category": row.get("Channel", "unknown"),
                        "summary": row.get("RuleTitle") or row.get("Details", "Hayabusa detection"),
                        "severity": severity,
                        "source": {
                            "tool": "hayabusa",
                            "rule_title": row.get("RuleTitle", "Unknown rule")
                        },
                        "evidence": {
                            "event_refs": [row.get("EventID", "")],
                            "artifacts": [row.get("EvtxFile", "")],
                            "raw": row
                        },
                        "host": {
                            "computer": row.get("Computer", "")
                        },
                        "_run_id": run_dir.name,
                        "_is_live": True
                    }
                    findings.append(finding)
        except Exception as e:
            print(f"Error loading Hayabusa CSV {csv_file}: {e}")
            continue
    
    return findings

async def _load_chainsaw_findings(case_id: str):
    """Load Chainsaw findings using case_id matching."""
    return await _load_tool_findings_by_case_id(case_id, "chainsaw", "chainsaw_evtx")

async def _load_hayabusa_findings(case_id: str):
    """Load Hayabusa findings using case_id matching."""
    return await _load_tool_findings_by_case_id(case_id, "hayabusa", "hayabusa_evtx")

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
    logger.info(f"[ARTIFACTS] Starting artifact discovery for case: {case_id}")
    
    case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
    if not case_dir.exists():
        logger.warning(f"[ARTIFACTS] Case directory not found: {case_dir}")
        return {"artifacts": []}
    
    found_artifacts = []
    processed_runs = set()
    scan_stats = {
        "directories_scanned": 0,
        "files_found": 0,
        "tools_matched": []
    }
    
    def scan_dir(d, prefix=""):
        if d.exists():
            scan_stats["directories_scanned"] += 1
            logger.debug(f"[ARTIFACTS] Scanning directory: {d}")
            for item in d.rglob("*"):
                if item.is_file() and not item.name.startswith(".") and not item.name.endswith(".py") and not item.name.endswith(".log"):
                    if item.suffix.lower() in [".csv", ".json", ".sqlite", ".txt", ".plaso", ".jsonl", ".db"]:
                        found_artifacts.append({
                            "name": item.name,
                            "relpath": f"{prefix}{item.name}",
                            "size": item.stat().st_size
                        })
                        scan_stats["files_found"] += 1
                        logger.debug(f"[ARTIFACTS] Found artifact: {item.name} in {d}")

    # 1. Check top level artifacts dir
    logger.info(f"[ARTIFACTS] Step 1: Checking case artifacts directory")
    scan_dir(case_dir / "artifacts", "artifacts/")
    
    # 2. Check orchestrator
    logger.info(f"[ARTIFACTS] Step 2: Checking orchestrator outputs")
    orch_dir = case_dir / "orchestrator"
    if orch_dir.exists():
        for run_dir in orch_dir.iterdir():
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                scan_dir(run_dir, f"orchestrator/{run_dir.name}/")
                
    # 3. Check Plaso
    logger.info(f"[ARTIFACTS] Step 3: Checking Plaso output")
    plaso_file = case_dir / f"{case_id}.plaso"
    if plaso_file.exists():
        logger.info(f"[ARTIFACTS] Found Plaso file: {plaso_file.name}")
        found_artifacts.append({
            "name": plaso_file.name,
            "relpath": f"supertimeline/{plaso_file.name}",
            "size": plaso_file.stat().st_size
        })

    # 4. Check auto.json (Chainsaw baseline)
    logger.info(f"[ARTIFACTS] Step 4: Checking auto.json for Chainsaw baseline")
    auto_json = case_dir / "auto.json"
    if auto_json.exists():
        try:
            with open(auto_json, "r") as f:
                auto_data = json.load(f)
            baseline_run_id = auto_data.get("dispatch", {}).get("run_id")
            if baseline_run_id:
                processed_runs.add(baseline_run_id)
                logger.info(f"[ARTIFACTS] Found Chainsaw baseline run_id: {baseline_run_id}")
                scan_dir(PROJECT_ROOT / "outputs" / "jsonl" / "chainsaw_evtx" / baseline_run_id, "chainsaw/")
                scan_dir(PROJECT_ROOT / "outputs" / "csv" / "chainsaw_evtx" / baseline_run_id, "chainsaw/")
        except Exception as e:
            logger.error(f"[ARTIFACTS] Error reading auto.json: {e}")

    # 5. Check enrichment.json (Hayabusa enrichment)
    logger.info(f"[ARTIFACTS] Step 5: Checking enrichment.json for Hayabusa")
    enrich_json = case_dir / "enrichment.json"
    if enrich_json.exists():
        try:
            with open(enrich_json, "r") as f:
                enrich_data = json.load(f)
            enrich_run_id = enrich_data.get("result", {}).get("run_id")
            if enrich_run_id:
                processed_runs.add(enrich_run_id)
                logger.info(f"[ARTIFACTS] Found Hayabusa enrichment run_id: {enrich_run_id}")
                scan_dir(PROJECT_ROOT / "outputs" / "jsonl" / "hayabusa_evtx" / enrich_run_id, "hayabusa/")
                scan_dir(PROJECT_ROOT / "outputs" / "csv" / "hayabusa_evtx" / enrich_run_id, "hayabusa/")
        except Exception as e:
            logger.error(f"[ARTIFACTS] Error reading enrichment.json: {e}")
    
    # 6. DISCOVER ALL TOOL OUTPUTS DYNAMICALLY
    logger.info(f"[ARTIFACTS] Step 6: Scanning all tool outputs dynamically")
    try:
        # Get the intake_id (UUID) from intake.json for matching
        intake_json = case_dir / "intake.json"
        target_intake_id = None
        if intake_json.exists():
            with open(intake_json, "r") as f:
                intake_data = json.load(f)
                # Support both V30 format (case_id) and legacy format (intake_id)
                target_intake_id = intake_data.get("case_id") or intake_data.get("intake_id")
                logger.info(f"[ARTIFACTS] Target intake_id for matching: {target_intake_id}")
        
        if target_intake_id:
            # Scan all tool output directories
            jsonl_base = PROJECT_ROOT / "outputs" / "jsonl"
            csv_base = PROJECT_ROOT / "outputs" / "csv"
            
            if jsonl_base.exists():
                for tool_dir in jsonl_base.iterdir():
                    if not tool_dir.is_dir():
                        continue
                    
                    tool_name = tool_dir.name
                    
                    logger.debug(f"[ARTIFACTS] Checking tool directory: {tool_name}")
                    
                    # Check each run directory in this tool's output
                    for run_dir in tool_dir.iterdir():
                        if not run_dir.is_dir():
                            continue
                            
                        # Skip if we already processed this exact run as a baseline/enrichment
                        if run_dir.name in processed_runs:
                            continue
                        
                        # Read request.json to match by case_id or run_id
                        request_json = run_dir / "request.json"
                        if request_json.exists():
                            try:
                                with open(request_json, "r") as f:
                                    req_data = json.load(f)
                                
                                is_match = False
                                match_method = None
                                
                                # Match by case_id in request.json (new format)
                                run_case_id = req_data.get("case_id")
                                if run_case_id and run_case_id == target_intake_id:
                                    is_match = True
                                    match_method = "case_id"
                                
                                # Match by run_id prefix (legacy format: run_id starts with intake_id)
                                if not is_match:
                                    run_id = req_data.get("run_id", "")
                                    if run_id.startswith(target_intake_id):
                                        is_match = True
                                        match_method = "run_id_prefix"
                                
                                if is_match:
                                    logger.info(f"[ARTIFACTS] ✓ MATCHED {tool_name}/{run_dir.name} via {match_method}")
                                    scan_stats["tools_matched"].append(f"{tool_name}/{run_dir.name}")
                                    # Found a matching run - scan its outputs
                                    scan_dir(run_dir, f"{tool_name}/{run_dir.name}/")
                                    
                                    # Also check for CSV output in parallel directory
                                    csv_run_dir = csv_base / tool_name / run_dir.name
                                    if csv_run_dir.exists():
                                        scan_dir(csv_run_dir, f"{tool_name}/{run_dir.name}/csv/")
                            except Exception as e:
                                logger.warning(f"[ARTIFACTS] Error reading {request_json}: {e}")
        else:
            logger.warning(f"[ARTIFACTS] No target_intake_id found - cannot match tool outputs")
    except Exception as e:
        logger.error(f"[ARTIFACTS] Error in dynamic tool discovery: {e}")
    
    # Remove duplicates if any
    unique_artifacts = {a["relpath"]: a for a in found_artifacts}.values()
    
    logger.info(f"[ARTIFACTS] Discovery complete: {len(unique_artifacts)} artifacts found")
    logger.info(f"[ARTIFACTS] Stats: {scan_stats}")

    return {"artifacts": list(unique_artifacts), "_debug": scan_stats}


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

# Evidence Drop Folder API Endpoints
@app.get("/api/evidence/drop-folder")
async def get_drop_folder_status():
    """Get the configured drop folder path and status."""
    try:
        config = load_drop_folder_config()
        drop_folder = Path(config["drop_folder"])
        exists = drop_folder.exists()
        
        return {
            "path": str(drop_folder),
            "exists": exists,
            "configured": True,
            "config": config,
            "message": "Drop folder configured" if exists else "Drop folder does not exist - will be created on first use"
        }
    except Exception as e:
        return {"error": str(e), "configured": False}

def list_drop_folder_items():
    """Fast scan - just list items in drop folder without deep classification."""
    config = load_drop_folder_config()
    drop_folder = Path(config["drop_folder"])
    
    if not drop_folder.exists():
        return {"error": "Drop folder not found", "evidence_items": []}
    
    items = []
    try:
        for item in sorted(drop_folder.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if item.is_dir() and not item.name.startswith("."):
                # Generate ID from path
                item_id = hashlib.md5(str(item).encode()).hexdigest()[:12]
                
                # Get basic stats
                stat = item.stat()
                
                items.append({
                    "id": item_id,
                    "name": item.name,
                    "path": str(item),
                    "type": "folder",
                    "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "size_bytes": stat.st_size,
                    "classification": None,  # Will be populated on-demand
                    "status": "pending"  # Will be updated after classification
                })
    except Exception as e:
        return {"error": str(e), "evidence_items": []}
    
    return {
        "drop_folder": str(drop_folder),
        "scanned_at": datetime.now().isoformat(),
        "evidence_items": items,
        "total_items": len(items)
    }

@app.get("/api/evidence/available")
async def get_available_evidence(refresh: bool = False):
    """
    Scan the drop folder and return available evidence.
    Fast listing - items shown immediately with "pending" status.
    """
    try:
        results = list_drop_folder_items()
        
        if "error" in results:
            raise HTTPException(status_code=500, detail=results["error"])
        
        return results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan drop folder: {str(e)}")

@app.post("/api/evidence/classify")
async def classify_evidence_item(path: str = Form(...)):
    """
    Classify a specific evidence item using identify_evidence.py.
    Called on-demand when user selects an item or clicks refresh.
    """
    try:
        evidence_path = Path(path)
        if not evidence_path.exists():
            raise HTTPException(status_code=404, detail=f"Evidence not found: {path}")
        
        # Run identify_evidence.py to classify
        cmd = [
            "python3",
            str(PROJECT_ROOT / "tools" / "intake" / "identify_evidence.py"),
            str(evidence_path),
            "--classify-only"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {
                "path": str(evidence_path),
                "name": evidence_path.name,
                "classification": {
                    "kind": "unknown",
                    "confidence": "low",
                    "description": "Classification failed",
                    "error": result.stderr
                },
                "status": "error"
            }
        
        try:
            classification = json.loads(result.stdout)
            return {
                "path": str(evidence_path),
                "name": evidence_path.name,
                "classification": classification,
                "status": "classified"
            }
        except json.JSONDecodeError:
            # If not JSON, parse the text output
            return {
                "path": str(evidence_path),
                "name": evidence_path.name,
                "classification": {
                    "kind": "unknown",
                    "confidence": "low",
                    "description": "Unable to parse classification",
                    "raw_output": result.stdout
                },
                "status": "parsed"
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/evidence/{evidence_id}/details")
async def get_evidence_item_details(evidence_id: str):
    """Get detailed information about a specific evidence item."""
    try:
        # List items to find by ID
        scan_results = list_drop_folder_items()
        
        for item in scan_results.get("evidence_items", []):
            if item["id"] == evidence_id:
                # If not classified yet, classify now
                if item.get("status") == "pending" or item.get("classification") is None:
                    # Run classification
                    cmd = [
                        "python3",
                        str(PROJECT_ROOT / "tools" / "intake" / "identify_evidence.py"),
                        item["path"],
                        "--classify-only"
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        try:
                            item["classification"] = json.loads(result.stdout)
                            item["status"] = "classified"
                        except:
                            pass
                
                return item
        
        raise HTTPException(status_code=404, detail=f"Evidence item with ID {evidence_id} not found")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cases/{case_id}/link-evidence")
async def link_evidence_to_case(
    case_id: str,
    evidence_paths: str = Form(...)
):
    """Create symlinks from case directory to external evidence."""
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        
        # Create evidence directory in case
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        
        paths = [p.strip() for p in evidence_paths.split(",") if p.strip()]
        linked = []
        failed = []
        
        for path_str in paths:
            source = Path(path_str)
            if not source.exists():
                failed.append({"path": path_str, "error": "Source not found"})
                continue
            
            try:
                # Create relative symlink
                link_name = evidence_dir / source.name
                
                # Remove existing link if present
                if link_name.exists() or link_name.is_symlink():
                    link_name.unlink()
                
                # Create symlink
                link_name.symlink_to(source.resolve(), target_is_directory=source.is_dir())
                
                linked.append({
                    "source": str(source),
                    "link": str(link_name),
                    "name": source.name
                })
            except Exception as e:
                failed.append({"path": path_str, "error": str(e)})
        
        return {
            "success": len(failed) == 0,
            "linked": linked,
            "failed": failed,
            "case_id": case_id,
            "evidence_dir": str(evidence_dir)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
    tools: str = Form(""),  # Comma-separated tool IDs (optional)
    use_ai: str = Form("false")  # Whether to use AI orchestrator
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
        ai_enabled = use_ai.lower() == 'true'
        
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
        
        # Extract case name from directory path (intake.json is in outputs/intake/{case_name}/)
        actual_case_name = intake_path.parent.name
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
                
                # PERSIST TOOL SELECTION: Save selected tools to intake.json
                # This ensures tool selection survives restarts and is available to all components
                intake_json_path = case_dir / "intake.json"
                if intake_json_path.exists():
                    try:
                        with open(intake_json_path, "r") as f:
                            intake_data = json.load(f)
                        
                        # Add selected_tools to intake data
                        intake_data["selected_tools"] = tool_list
                        intake_data["tool_selection_timestamp"] = datetime.now().isoformat()
                        
                        with open(intake_json_path, "w") as f:
                            json.dump(intake_data, f, indent=2)
                        
                        print(f"Saved selected tools to intake.json: {tool_list}")
                    except Exception as e:
                        print(f"Warning: Could not save tool selection to intake.json: {e}")
                
                # Run dfir.py in background
                # IMPORTANT: Pass the intake.json path, NOT the raw evidence path
                # This prevents dfir.py from recreating the case
                dfir_script = PROJECT_ROOT / "dfir.py"
                cmd = ["python3", str(dfir_script), str(intake_json_path)]
                
                # Pass selected tools to dfir.py
                if tool_list:
                    cmd.extend(["--selected-tools", ",".join(tool_list)])
                
                # Add --skip-orchestrator flag if AI mode is disabled
                if not ai_enabled:
                    cmd.append("--skip-orchestrator")
                    print(f"AI mode disabled - skipping orchestrator for case {actual_case_name}")
                
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
                status["current_action"] = f"Running dfir.py (PID: {process.pid})..."
                status["logs"].append(f"[{datetime.now().isoformat()}] Investigation started with command: {' '.join(cmd)}")
                status["log_file"] = str(log_file_path)
                status["command"] = ' '.join(cmd)
                
                print(f"Started investigation for case {actual_case_name} with PID {process.pid}")
                print(f"Command: {' '.join(cmd)}")
                print(f"Log file: {log_file_path}")
                
                with open(status_file, "w") as f:
                    json.dump(status, f, indent=2)
        else:
            print(f"No tools selected for case {actual_case_name}, skipping investigation start")
        
        # Return immediately - UI can update
        return {
            "success": True,
            "case_name": actual_case_name,
            "display_name": actual_case_name,  # Use case_name as display_name since display_name removed from intake.json
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
        
        # Build command - dfir.py takes intake.json path as argument
        # Pass intake.json instead of raw evidence path to avoid recreating the case
        cmd = [
            "python3",
            str(dfir_script),
            str(intake_json)
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
        
        # PERSIST TOOL SELECTION: Save selected tools to intake.json
        # This ensures tool selection survives restarts and is available to all components
        if intake_json.exists():
            try:
                with open(intake_json, "r") as f:
                    intake_data = json.load(f)
                
                # Add selected_tools to intake data
                intake_data["selected_tools"] = tool_list
                intake_data["tool_selection_timestamp"] = datetime.now().isoformat()
                
                with open(intake_json, "w") as f:
                    json.dump(intake_data, f, indent=2)
                
                print(f"Saved selected tools to intake.json: {tool_list}")
            except Exception as e:
                print(f"Warning: Could not save tool selection to intake.json: {e}")
        
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

@app.post("/api/investigate/add-tools")
async def add_tools_to_investigation(
    case_name: str = Form(...),
    tools: str = Form(...)  # Comma-separated tool IDs to add
):
    """Add tools to an existing investigation.
    
    This allows running additional tools on a case after initial investigation.
    Tools will be appended to the selected_tools list in intake.json.
    """
    try:
        tool_list = [t.strip() for t in tools.split(",") if t.strip()]
        
        if not tool_list:
            raise HTTPException(status_code=400, detail="No tools specified")
        
        # Check if case exists
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_name
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_name}' not found")
        
        # Load intake.json
        intake_json = case_dir / "intake.json"
        if not intake_json.exists():
            raise HTTPException(status_code=404, detail="Case intake.json not found")
        
        with open(intake_json, "r") as f:
            intake_data = json.load(f)
        
        # Get existing selected_tools or initialize empty list
        existing_tools = intake_data.get("selected_tools", [])
        
        # Add new tools (avoid duplicates)
        added_tools = []
        for tool in tool_list:
            if tool not in existing_tools:
                existing_tools.append(tool)
                added_tools.append(tool)
        
        # Update intake.json
        intake_data["selected_tools"] = existing_tools
        intake_data["tool_selection_timestamp"] = datetime.now().isoformat()
        
        with open(intake_json, "w") as f:
            json.dump(intake_data, f, indent=2)
        
        # Update investigation status
        status_file = case_dir / "investigation_status.json"
        if status_file.exists():
            with open(status_file, "r") as f:
                status = json.load(f)
            
            # Merge new tools with existing
            current_tools = status.get("tools", [])
            for tool in tool_list:
                if tool not in current_tools:
                    current_tools.append(tool)
            
            status["tools"] = current_tools
            status["logs"].append(f"[{datetime.now().isoformat()}] Added tools: {added_tools}")
            
            with open(status_file, "w") as f:
                json.dump(status, f, indent=2)
        
        # Trigger dispatch for new tools
        # Run dispatch_intake.py to execute only the new tools
        dispatch_script = PROJECT_ROOT / "tools" / "router" / "dispatch_intake.py"
        
        if added_tools:
            cmd = [
                "python3",
                str(dispatch_script),
                "--intake-json", str(intake_json),
                "--selected-tools", ",".join(added_tools)
            ]
            
            env = os.environ.copy()
            env["DFIR_CASE_NAME"] = case_name
            
            # Run dispatch in background
            process = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                start_new_session=True
            )
            
            return {
                "success": True,
                "case_name": case_name,
                "added_tools": added_tools,
                "total_tools": existing_tools,
                "dispatch_pid": process.pid,
                "message": f"Added {len(added_tools)} tool(s) and started dispatch process"
            }
        else:
            return {
                "success": True,
                "case_name": case_name,
                "added_tools": [],
                "total_tools": existing_tools,
                "message": "No new tools to add (all already selected)"
            }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/investigate/status/{case_name}")
async def get_investigation_status(case_name: str):
    """Get merged status from all sources: investigation_status, auto.json, and progress.json."""
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_name
        
        if not case_dir.exists():
            return {"status": "not_found", "case_name": case_name}
        
        # Read all status sources
        sources = {
            "investigation_status": {},
            "auto": {},
            "progress": {},
            "intake": {}
        }
        
        # 1. investigation_status.json (initial state, may be stale)
        status_file = case_dir / "investigation_status.json"
        if status_file.exists():
            try:
                with open(status_file, "r") as f:
                    sources["investigation_status"] = json.load(f)
            except:
                pass
        
        # 2. auto.json (stage completion status - most accurate for tool completion)
        auto_file = case_dir / "auto.json"
        if auto_file.exists():
            try:
                with open(auto_file, "r") as f:
                    sources["auto"] = json.load(f)
            except:
                pass
        
        # 3. progress.json (real-time tool progress)
        progress_file = case_dir / "progress.json"
        if progress_file.exists():
            try:
                with open(progress_file, "r") as f:
                    progress_data = json.load(f)
                    if isinstance(progress_data, list) and progress_data:
                        sources["progress"] = progress_data[-1]  # Latest update
            except:
                pass
        
        # 4. intake.json (selected tools)
        intake_file = case_dir / "intake.json"
        if intake_file.exists():
            try:
                with open(intake_file, "r") as f:
                    sources["intake"] = json.load(f)
            except:
                pass
        
        # Get selected tools
        selected_tools = sources["intake"].get("selected_tools", [])
        stages = sources["auto"].get("stages", {})
        progress = sources["progress"]
        
        # Calculate completion status
        if selected_tools and stages:
            completed_tools = []
            failed_tools = []
            running_tool = None
            
            for tool in selected_tools:
                status = stages.get(tool, "pending")
                if status == "ok" or status.startswith("ok"):
                    completed_tools.append(tool)
                elif status.startswith("error"):
                    failed_tools.append(tool)
                elif status == "running":
                    running_tool = tool
            
            total_selected = len(selected_tools)
            total_done = len(completed_tools) + len(failed_tools)
            
            # Calculate progress
            if total_selected > 0:
                progress_pct = int((total_done / total_selected) * 100)
            else:
                progress_pct = 0
            
            # Determine if all tools finished
            all_finished = total_done >= total_selected
            
            # Build response
            if all_finished:
                return {
                    "status": "completed",
                    "case_name": case_name,
                    "progress": 100,
                    "current_tool": "completed",
                    "current_action": f"Investigation complete - {len(completed_tools)} tools finished",
                    "completed_tools": completed_tools,
                    "failed_tools": failed_tools,
                    "total_tools": total_selected
                }
            elif running_tool:
                # Get progress details from progress.json if available
                action = f"Running {running_tool}..."
                tool_progress = 10
                
                if progress and progress.get("tool_id") == running_tool:
                    action = progress.get("current_action", action)
                    tool_progress = progress.get("progress", 10)
                
                return {
                    "status": "running",
                    "case_name": case_name,
                    "progress": progress_pct,
                    "current_tool": running_tool,
                    "current_action": action,
                    "completed_tools": completed_tools,
                    "pending_tools": [t for t in selected_tools if t not in completed_tools and t not in failed_tools and t != running_tool],
                    "total_tools": total_selected
                }
            else:
                # Waiting to start or initializing
                return {
                    "status": "starting",
                    "case_name": case_name,
                    "progress": progress_pct,
                    "current_tool": "initializing",
                    "current_action": "Preparing forensic tools...",
                    "completed_tools": completed_tools,
                    "total_tools": total_selected
                }
        
        # Fallback to investigation_status.json if no auto.json yet
        if sources["investigation_status"]:
            inv = sources["investigation_status"]
            return {
                "status": inv.get("status", "starting"),
                "case_name": case_name,
                "progress": inv.get("progress", 0),
                "current_tool": inv.get("current_tool", "initializing"),
                "current_action": inv.get("current_action", "Initializing..."),
                "total_tools": len(inv.get("tools", []))
            }
        
        # No status files found
        return {
            "status": "unknown",
            "case_name": case_name,
            "progress": 0,
            "current_tool": "unknown",
            "current_action": "Status unknown - check if investigation was started"
        }
        
    except Exception as e:
        logger.error(f"Error getting status for {case_name}: {e}")
        return {
            "status": "error",
            "case_name": case_name,
            "error": str(e)
        }

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

@app.post("/api/investigate/{case_id}/run-tools")
async def run_tools_on_case(
    case_id: str,
    tools: str = Form(...),  # Comma-separated tool IDs
):
    """
    Run specific tools on an existing case on-demand.
    This allows adding analysis capabilities after the initial investigation.
    Tools that already completed (status 'ok' in auto.json) will be skipped
    by auto_run.py since they already have output.
    """
    try:
        tool_list = [t.strip() for t in tools.split(",") if t.strip()]
        if not tool_list:
            raise HTTPException(status_code=400, detail="No tools specified")

        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

        intake_json = case_dir / "intake.json"
        if not intake_json.exists():
            raise HTTPException(status_code=404, detail="Case intake.json not found")

        # Check if an investigation is already running
        status_file = case_dir / "investigation_status.json"
        if status_file.exists():
            try:
                with open(status_file, "r") as f:
                    existing_status = json.load(f)
                pid = existing_status.get("pid")
                if pid:
                    try:
                        os.kill(pid, 0)
                        raise HTTPException(
                            status_code=409,
                            detail=f"Investigation already running (PID {pid}). Wait for it to finish."
                        )
                    except (OSError, ProcessLookupError):
                        pass  # Process is dead, safe to proceed
            except (json.JSONDecodeError, Exception):
                pass

        # Update intake.json with the new tool selection
        with open(intake_json, "r") as f:
            intake_data = json.load(f)

        intake_data["selected_tools"] = tool_list
        intake_data["tool_selection_timestamp"] = datetime.now().isoformat()

        with open(intake_json, "w") as f:
            json.dump(intake_data, f, indent=2)

        # Create a fresh investigation_status.json
        status = {
            "status": "starting",
            "started_at": datetime.now().isoformat(),
            "tools": tool_list,
            "completed_tools": [],
            "current_tool": "initializing",
            "current_action": "Starting on-demand tool execution...",
            "progress": 0,
            "logs": [f"[{datetime.now().isoformat()}] On-demand run: {tool_list}"],
            "pid": None
        }
        with open(status_file, "w") as f:
            json.dump(status, f, indent=2)

        # Launch dfir.py in background with --selected-tools and --skip-orchestrator
        dfir_script = PROJECT_ROOT / "dfir.py"
        cmd = [
            "python3", str(dfir_script),
            str(intake_json),
            "--selected-tools", ",".join(tool_list),
            "--skip-orchestrator"
        ]

        env = os.environ.copy()
        env["DFIR_CASE_NAME"] = case_id

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

        status["pid"] = process.pid
        status["status"] = "running"
        status["current_action"] = f"Running tools (PID: {process.pid})..."
        status["log_file"] = str(log_file_path)
        status["command"] = " ".join(cmd)

        with open(status_file, "w") as f:
            json.dump(status, f, indent=2)

        print(f"On-demand tool run for case {case_id}: tools={tool_list}, PID={process.pid}")

        return {
            "success": True,
            "case_id": case_id,
            "tools": tool_list,
            "pid": process.pid,
            "message": f"Started {len(tool_list)} tool(s) in background"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/cases/{case_id}/progress")
async def get_tool_progress(case_id: str):
    """Get real-time progress updates for tools.
    
    Returns progress.json contents showing:
    - Current tool being executed
    - Progress percentage (0-100)
    - Status (initializing, running, completed, error, skipped)
    - Current action description
    - Timestamp of last update
    """
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        
        progress_file = case_dir / "progress.json"
        
        if not progress_file.exists():
            # No progress updates yet - return empty but valid response
            return {
                "case_id": case_id,
                "updates": [],
                "latest": None,
                "has_progress": False
            }
        
        try:
            with open(progress_file, "r") as f:
                updates = json.load(f)
            
            if not isinstance(updates, list):
                updates = [updates] if updates else []
            
            # Get latest update
            latest = updates[-1] if updates else None
            
            return {
                "case_id": case_id,
                "updates": updates,
                "latest": latest,
                "has_progress": len(updates) > 0,
                "total_updates": len(updates)
            }
            
        except json.JSONDecodeError:
            return {
                "case_id": case_id,
                "updates": [],
                "latest": None,
                "has_progress": False,
                "error": "Invalid progress file format"
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/cases/{case_id}/debug")
async def debug_case(case_id: str):
    """Debug endpoint for comprehensive case diagnostics.
    
    Provides detailed information about:
    - Case directory structure
    - Tool outputs discovered
    - Auto.json and enrichment.json status
    - Progress calculation data
    - Intake.json contents
    - Artifact discovery details
    """
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        
        debug_info = {
            "case_id": case_id,
            "timestamp": datetime.now().isoformat(),
            "case_exists": case_dir.exists(),
            "case_path": str(case_dir),
            "directories": {},
            "files": {},
            "config": {},
            "stages": {},
            "artifacts": {},
            "logs": []
        }
        
        if not case_dir.exists():
            return {"error": f"Case directory not found: {case_dir}", "debug": debug_info}
        
        # 1. Directory structure
        for subdir in case_dir.iterdir():
            if subdir.is_dir():
                file_count = len(list(subdir.rglob("*")))
                debug_info["directories"][subdir.name] = {
                    "exists": True,
                    "file_count": file_count
                }
        
        # 2. Check key files
        key_files = {
            "intake.json": case_dir / "intake.json",
            "auto.json": case_dir / "auto.json",
            "enrichment.json": case_dir / "enrichment.json",
            "investigation_status.json": case_dir / "investigation_status.json",
            "investigation.log": case_dir / "investigation.log"
        }
        
        for name, path in key_files.items():
            if path.exists():
                try:
                    size = path.stat().st_size
                    mtime = datetime.fromtimestamp(path.stat().st_mtime).isoformat()
                    
                    if path.suffix == '.json':
                        with open(path) as f:
                            content = json.load(f)
                        debug_info["files"][name] = {
                            "exists": True,
                            "size": size,
                            "modified": mtime,
                            "content": content
                        }
                    else:
                        # For log files, show last 20 lines
                        with open(path, 'r', errors='ignore') as f:
                            lines = f.readlines()
                        debug_info["files"][name] = {
                            "exists": True,
                            "size": size,
                            "modified": mtime,
                            "line_count": len(lines),
                            "last_20_lines": lines[-20:] if len(lines) >= 20 else lines
                        }
                except Exception as e:
                    debug_info["files"][name] = {"exists": True, "error": str(e)}
            else:
                debug_info["files"][name] = {"exists": False}
        
        # 3. Get artifact discovery details
        artifacts_response = await get_generated_artifacts(case_id)
        debug_info["artifacts"] = {
            "count": len(artifacts_response.get("artifacts", [])),
            "artifacts": artifacts_response.get("artifacts", []),
            "discovery_stats": artifacts_response.get("_debug", {})
        }
        
        # 4. Get status details
        status_response = await get_investigation_status(case_id)
        debug_info["status"] = status_response
        
        # 5. Check tool output directories
        tool_outputs = {}
        jsonl_base = PROJECT_ROOT / "outputs" / "jsonl"
        if jsonl_base.exists():
            for tool_dir in jsonl_base.iterdir():
                if tool_dir.is_dir():
                    tool_name = tool_dir.name
                    runs = []
                    for run_dir in tool_dir.iterdir():
                        if run_dir.is_dir():
                            req_json = run_dir / "request.json"
                            case_id_match = None
                            if req_json.exists():
                                try:
                                    with open(req_json) as f:
                                        req_data = json.load(f)
                                    case_id_match = req_data.get("case_id")
                                except:
                                    pass
                            runs.append({
                                "run_id": run_dir.name,
                                "request_json_exists": req_json.exists(),
                                "case_id_in_request": case_id_match
                            })
                    if runs:
                        tool_outputs[tool_name] = runs
        
        debug_info["tool_outputs"] = tool_outputs
        
        # 6. Calculate what progress should be
        if "files" in debug_info and "intake.json" in debug_info["files"]:
            intake_data = debug_info["files"]["intake.json"].get("content", {})
            selected_tools = intake_data.get("selected_tools", [])
            
            if selected_tools and "files" in debug_info and "auto.json" in debug_info["files"]:
                auto_data = debug_info["files"]["auto.json"].get("content", {})
                stages = auto_data.get("stages", {})
                
                completed = sum(1 for tool in selected_tools 
                              if tool in stages and (stages[tool] == "ok" or 
                                                    stages[tool].startswith("ok") or 
                                                    stages[tool].startswith("error")))
                
                debug_info["progress_calculation"] = {
                    "selected_tools": selected_tools,
                    "completed_count": completed,
                    "total_selected": len(selected_tools),
                    "calculated_progress": int((completed / len(selected_tools)) * 100) if selected_tools else 0,
                    "stage_statuses": {tool: stages.get(tool, "not in stages") for tool in selected_tools}
                }
        
        return {"success": True, "debug": debug_info}
        
    except Exception as e:
        import traceback
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def run_server(host="0.0.0.0", port=8080):
    import uvicorn
    print(f"Starting DFIR-Agentic Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


# =============================================================================
# CONSOLIDATED DASHBOARD STATUS ENDPOINT
# Returns all panel data in a single call for efficient polling
# =============================================================================

@app.get("/api/cases/{case_id}/dashboard-status")
async def get_dashboard_status(case_id: str):
    """Get complete dashboard status for all panels in a single call.
    
    This consolidated endpoint reduces API calls from 10+ to 1 per poll cycle,
    significantly reducing bandwidth and server load.
    
    Returns:
        {
            "case_id": "...",
            "timestamp": "...",
            "overview": {...},
            "progress": {...},
            "artifacts": {...},
            "findings": {...},
            "notes": {...},
            "audit": {...}
        }
    """
    try:
        case_dir = PROJECT_ROOT / "outputs" / "intake" / case_id
        
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        
        # Read all necessary files once and share across panel data
        intake_data = {}
        manifest_data = {}
        auto_data = {}
        progress_data = {}
        
        # 1. Read intake.json
        intake_path = case_dir / "intake.json"
        if intake_path.exists():
            try:
                with open(intake_path, "r", encoding="utf-8") as f:
                    intake_data = json.load(f)
            except:
                pass
        
        # 2. Read case_manifest.json
        manifest_path = case_dir / "case_manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            except:
                pass
        
        # 3. Read auto.json (tool stages)
        auto_path = case_dir / "auto.json"
        if auto_path.exists():
            try:
                with open(auto_path, "r", encoding="utf-8") as f:
                    auto_data = json.load(f)
            except:
                pass
        
        # 4. Read progress.json (real-time tool progress)
        progress_path = case_dir / "progress.json"
        if progress_path.exists():
            try:
                with open(progress_path, "r", encoding="utf-8") as f:
                    progress_list = json.load(f)
                    if isinstance(progress_list, list) and progress_list:
                        progress_data = progress_list[-1]  # Latest entry
            except:
                pass
        
        # 5. Get investigation status (merged from investigation_status.json)
        inv_status_path = case_dir / "investigation_status.json"
        inv_status = {}
        if inv_status_path.exists():
            try:
                with open(inv_status_path, "r", encoding="utf-8") as f:
                    inv_status = json.load(f)
            except:
                pass
        
        # ===================================================================
        # Build OVERVIEW panel data
        # ===================================================================
        is_active = True
        if auto_data.get("stages", {}):
            stages = auto_data["stages"]
            # Check if all tools finished
            selected_tools = intake_data.get("selected_tools", [])
            if selected_tools:
                all_done = all(
                    stages.get(tool, "").startswith("ok") or 
                    stages.get(tool, "").startswith("error") or
                    stages.get(tool, "") == "skipped"
                    for tool in selected_tools
                )
                is_active = not all_done
        
        overview = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "id": case_id,
            "intake": intake_data,
            "manifest": manifest_data,
            "is_active": is_active,
            "auto_stages": auto_data.get("stages", {}),
            "classification": intake_data.get("classification", {}),
            "timestamp_utc": intake_data.get("timestamp_utc", "")
        }
        
        # Generate hash for smart caching
        overview["_hash"] = hash(f"{case_id}:{overview['is_active']}:{str(overview['auto_stages'])}")
        
        # ===================================================================
        # Build PROGRESS panel data
        # ===================================================================
        selected_tools = intake_data.get("selected_tools", [])
        stages = auto_data.get("stages", {})
        
        completed_tools = []
        failed_tools = []
        running_tool = None
        
        for tool in selected_tools:
            status = stages.get(tool, "pending")
            if status == "ok" or status.startswith("ok"):
                completed_tools.append(tool)
            elif status.startswith("error"):
                failed_tools.append(tool)
            elif status == "running":
                running_tool = tool
        
        total_selected = len(selected_tools)
        total_done = len(completed_tools) + len(failed_tools)
        
        if total_selected > 0:
            progress_pct = int((total_done / total_selected) * 100)
        else:
            progress_pct = 0
        
        all_finished = total_done >= total_selected
        
        if all_finished:
            progress_status = "completed"
            current_tool = "completed"
            current_action = f"Investigation complete - {len(completed_tools)} tools finished"
        elif running_tool:
            progress_status = "running"
            current_tool = running_tool
            action = f"Running {running_tool}..."
            tool_progress = 10
            if progress_data and progress_data.get("tool_id") == running_tool:
                action = progress_data.get("current_action", action)
                tool_progress = progress_data.get("progress", 10)
            current_action = action
        else:
            progress_status = "starting"
            current_tool = "initializing"
            current_action = "Preparing forensic tools..."
        
        pending_tools = [t for t in selected_tools if t not in completed_tools and t not in failed_tools and t != running_tool]
        
        progress = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "status": progress_status,
            "case_name": case_id,
            "progress": progress_pct,
            "current_tool": current_tool,
            "current_action": current_action,
            "completed_tools": completed_tools,
            "failed_tools": failed_tools,
            "pending_tools": pending_tools,
            "total_tools": total_selected,
            "tool_progress": progress_data
        }
        
        # Generate hash for smart caching
        progress["_hash"] = hash(f"{progress_status}:{progress_pct}:{current_tool}:{','.join(completed_tools)}:{','.join(pending_tools)}")
        
        # ===================================================================
        # Build ARTIFACTS panel data
        # ===================================================================
        artifacts_response = await get_generated_artifacts(case_id)
        artifacts_list = artifacts_response.get("artifacts", [])
        
        # Calculate artifacts hash based on file list
        artifacts_hash_str = ",".join(sorted([a["relpath"] for a in artifacts_list]))
        
        artifacts = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "artifacts": artifacts_list,
            "count": len(artifacts_list),
            "_hash": hash(artifacts_hash_str)
        }
        
        # ===================================================================
        # Build FINDINGS panel data
        # ===================================================================
        try:
            findings_response = await get_findings(case_id, None)
            findings_list = findings_response.get("findings", [])
        except:
            findings_list = []
        
        # Calculate findings hash
        finding_ids = sorted([f.get("finding_id", f.get("id", "")) for f in findings_list])
        findings_hash_str = ",".join(finding_ids[:100])  # Limit to first 100
        
        findings = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "findings": findings_list,
            "count": len(findings_list),
            "_hash": hash(f"{len(findings_list)}:{findings_hash_str}")
        }
        
        # ===================================================================
        # Build NOTES panel data
        # ===================================================================
        notes_content = ""
        try:
            notes_response = await get_notes(case_id)
            notes_content = notes_response.get("notes", "")
        except:
            pass
        
        notes = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "content": notes_content,
            "_hash": hash(notes_content[:1000])  # Hash first 1000 chars
        }
        
        # ===================================================================
        # Build AUDIT panel data
        # ===================================================================
        audit_entries = []
        try:
            audit_response = await get_audit(case_id)
            audit_entries = audit_response.get("audit", [])
        except:
            pass
        
        # Calculate audit hash
        audit_hash_str = ",".join([str(a.get("timestamp", "")) for a in audit_entries[:50]])
        
        audit = {
            "_last_updated": datetime.now(timezone.utc).isoformat(),
            "entries": audit_entries,
            "count": len(audit_entries),
            "_hash": hash(f"{len(audit_entries)}:{audit_hash_str}")
        }
        
        # ===================================================================
        # Assemble final response
        # ===================================================================
        return {
            "case_id": case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_active": is_active,
            "overview": overview,
            "progress": progress,
            "artifacts": artifacts,
            "findings": findings,
            "notes": notes,
            "audit": audit
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"[DASHBOARD-STATUS] Error getting status for {case_id}: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


# Cache for file reads (1 second TTL to avoid re-reading same files)
_file_cache = {}
_file_cache_ttl = 1.0  # seconds

def _read_file_cached(path: Path) -> dict:
    """Read a JSON file with caching to avoid repeated reads within 1 second."""
    global _file_cache
    
    now = time.time()
    cache_key = str(path)
    
    if cache_key in _file_cache:
        cached_data, cached_time = _file_cache[cache_key]
        if now - cached_time < _file_cache_ttl:
            return cached_data
    
    # Read fresh
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        _file_cache[cache_key] = (data, now)
        return data
    except:
        return {}


if __name__ == "__main__":
    run_server()
