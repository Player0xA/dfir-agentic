#!/usr/bin/env python3
import json
import os
import sys
import uuid
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple

# ----------------------------
# Policy (v0.1)
# ----------------------------
PROJECT_ROOT = Path.cwd()

# Evidence roots are where "identify_evidence" and "auto_run" are allowed to point.
# Keep this conservative; expand later as needed.
ALLOWED_EVIDENCE_ROOTS = [
    Path("/home/nevermore/cases"),
    PROJECT_ROOT / "cases",  # optional local
]

# Read-only roots for read_json/list_dir tools
ALLOWED_READ_ROOTS = [
    PROJECT_ROOT / "outputs",
    PROJECT_ROOT / "contracts",
]

AUDIT_ROOT = PROJECT_ROOT / "outputs" / "mcp_runs"

HAYABUSA_ROOT = PROJECT_ROOT / "tools" / "hayabusa"
HAYABUSA_BIN = HAYABUSA_ROOT / "bin" / "hayabusa"
HAYABUSA_RULES = HAYABUSA_ROOT / "rules"
HAYABUSA_CONFIG = HAYABUSA_RULES / "config"
PSORT_BIN = "/home/nevermore/bin/psort"


TOOLS = [
    {
        "name": "dfir.identify_evidence@1",
        "description": "Deterministically identify evidence and write outputs/intake/<id>/intake.json",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1}
            }
        }
    },
    {
        "name": "dfir.auto_run@1",
        "description": "Run autonomous local protocol (select_agent -> enforce -> dispatch -> validate) and write auto.json next to intake.json",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["intake_json"],
            "properties": {
                "intake_json": {"type": "string", "minLength": 1}
            }
        }
    },
    {
        "name": "dfir.read_json@1",
        "description": "Read a JSON file under outputs/ or contracts/ with optional JSON Pointer, bounded by max_bytes",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "json_pointer": {"type": ["string", "null"]},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576}
            }
        }
    },
        {
        "name": "dfir.hayabusa_csv_timeline@1",
        "description": "Run Hayabusa csv-timeline deterministically on an EVTX directory and write outputs/csv/hayabusa_evtx/<run_id>/timeline.csv",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evtx_dir"],
            "properties": {
                "evtx_dir": {"type": "string", "minLength": 1},
                "profile": {"type": "string", "minLength": 1, "default": "verbose"},
                "iso_utc": {"type": "boolean", "default": True},
                "no_wizard": {"type": "boolean", "default": True},
                "clobber": {"type": "boolean", "default": True}
            }
        }
    },
    {
        "name": "dfir.list_dir@1",
        "description": "List directory entries under outputs/ or contracts/",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1}
            }
        }
    },
    {
        "name": "dfir.query_super_timeline@1",
        "description": "Query a Plaso .plaso storage file using psort.py with a time-slice window",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["plaso_file", "start_time", "end_time"],
            "properties": {
                "plaso_file": {"type": "string", "minLength": 1, "description": "Path to the .plaso file"},
                "start_time": {"type": "string", "description": "ISO8601 UTC start time (e.g., 2026-02-11T23:00:00Z)"},
                "end_time": {"type": "string", "description": "ISO8601 UTC end time"},
                "artifact_filter": {"type": "string", "description": "Optional Plaso filter expression (e.g. 'parser is winevtx')"},
                "output_format": {"type": "string", "enum": ["json", "csv"], "default": "json"}
            }
        }
    }
]

# ----------------------------
# Helpers
# ----------------------------
def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def jsonrpc_ok(_id, result):
    return {"jsonrpc": "2.0", "id": _id, "result": result}

def jsonrpc_err(_id, code: int, message: str, data: Optional[dict] = None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": _id, "error": err}

def write_line(obj: dict):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def safe_resolve(p: str) -> Path:
    # Accept relative paths; resolve against project root
    path = Path(p)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    else:
        path = path.resolve()
    return path

def under_any_root(path: Path, roots: List[Path]) -> bool:
    for r in roots:
        rr = r.resolve()
        try:
            path.relative_to(rr)
            return True
        except Exception:
            continue
    return False

def ensure_read_allowed(path: Path) -> None:
    if not under_any_root(path, ALLOWED_READ_ROOTS):
        raise PermissionError(f"read denied: path outside allowed roots: {path}")

def ensure_evidence_allowed(path: Path) -> None:
    if not under_any_root(path, ALLOWED_EVIDENCE_ROOTS):
        raise PermissionError(f"evidence denied: path outside allowed evidence roots: {path}")

def mkdirp(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def audit_paths(call_id: str) -> Dict[str, Path]:
    base = AUDIT_ROOT / call_id
    return {
        "base": base,
        "request": base / "request.json",
        "response": base / "response.json",
        "stdout": base / "stdout.log",
        "stderr": base / "stderr.log",
        "meta": base / "meta.json",
    }

def audit_write(paths: Dict[str, Path], name: str, content: str):
    if name not in paths:
        return
    p = paths[name]
    p.write_text(content, encoding="utf-8")

def run_cmd(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def parse_ok_wrote_path(stdout: str) -> Optional[str]:
    # Expected line: "OK: wrote outputs/intake/<id>/intake.json"
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("OK: wrote "):
            return line[len("OK: wrote "):].strip()
    return None

def json_pointer_get(doc: Any, ptr: Optional[str]) -> Any:
    if ptr is None or ptr == "" or ptr == "/":
        return doc
    if not ptr.startswith("/"):
        raise ValueError("json_pointer must start with '/'")
    cur = doc
    parts = ptr.split("/")[1:]
    for raw in parts:
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            idx = int(part)
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"cannot descend into non-container at '{part}'")
    return cur

# ----------------------------
# Tool implementations
# ----------------------------
def tool_identify_evidence(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    evidence_path = safe_resolve(args["path"])
    ensure_evidence_allowed(evidence_path)

    cmd = [str(PROJECT_ROOT / "tools/intake/identify_evidence.py"), str(evidence_path)]
    rc, out, err = run_cmd(cmd, cwd=PROJECT_ROOT)
    audit_write(audit, "stdout", out)
    audit_write(audit, "stderr", err)

    if rc != 0:
        raise RuntimeError(f"identify_evidence failed (rc={rc})")

    intake_path = parse_ok_wrote_path(out)
    if not intake_path:
        raise RuntimeError("identify_evidence did not report output path")

    intake_abs = safe_resolve(intake_path)
    ensure_read_allowed(intake_abs)

    # Validate intake (hard gate)
    vcmd = [
        str(PROJECT_ROOT / "tools/contracts/validate_intake.py"),
        str(PROJECT_ROOT / "contracts/intake.schema.json"),
        str(intake_abs),
    ]
    rc2, out2, err2 = run_cmd(vcmd, cwd=PROJECT_ROOT)
    audit_write(audit, "stdout", (audit["stdout"].read_text(encoding="utf-8") if audit["stdout"].exists() else "") + out2)
    audit_write(audit, "stderr", (audit["stderr"].read_text(encoding="utf-8") if audit["stderr"].exists() else "") + err2)
    if rc2 != 0:
        raise RuntimeError("intake validation failed")

    return {"intake_json": str(intake_abs)}

def tool_auto_run(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    intake_path = safe_resolve(args["intake_json"])
    ensure_read_allowed(intake_path)

    # For safety, ensure the intake.json itself refers to evidence under allowed evidence roots.
    try:
        intake_doc = json.loads(intake_path.read_text(encoding="utf-8"))
        ev = intake_doc["inputs"]["paths"][0]
        ev_path = safe_resolve(ev)
        ensure_evidence_allowed(ev_path)
    except Exception as ex:
        raise PermissionError(f"intake evidence root check failed: {ex}")

    cmd = [str(PROJECT_ROOT / "tools/router/auto_run.py"), "--intake-json", str(intake_path)]
    rc, out, err = run_cmd(cmd, cwd=PROJECT_ROOT)
    audit_write(audit, "stdout", out)
    audit_write(audit, "stderr", err)
    if rc != 0:
        raise RuntimeError(f"auto_run failed (rc={rc})")

    auto_path = intake_path.parent / "auto.json"
    if not auto_path.is_file():
        raise RuntimeError(f"auto.json not found: {auto_path}")

    # Validate auto.json (hard gate)
    vcmd = [
        str(PROJECT_ROOT / "tools/contracts/validate_auto.py"),
        str(PROJECT_ROOT / "contracts/auto.schema.json"),
        str(auto_path),
    ]
    rc2, out2, err2 = run_cmd(vcmd, cwd=PROJECT_ROOT)
    audit_write(audit, "stdout", (audit["stdout"].read_text(encoding="utf-8") if audit["stdout"].exists() else "") + out2)
    audit_write(audit, "stderr", (audit["stderr"].read_text(encoding="utf-8") if audit["stderr"].exists() else "") + err2)
    if rc2 != 0:
        raise RuntimeError("auto validation failed")

    return {"auto_json": str(auto_path)}

def tool_hayabusa_csv_timeline(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    evtx_dir = safe_resolve(args["evtx_dir"])
    ensure_evidence_allowed(evtx_dir)
    if not evtx_dir.is_dir():
        raise ValueError(f"evtx_dir is not a directory: {evtx_dir}")

    if not HAYABUSA_BIN.is_file():
        raise RuntimeError(f"hayabusa bin not found: {HAYABUSA_BIN}")

    # Hard gate: must have rules + config where we expect them
    required = [
        HAYABUSA_CONFIG / "channel_abbreviations.txt",
        HAYABUSA_CONFIG / "provider_abbreviations.txt",
        HAYABUSA_CONFIG / "default_details.txt",
        HAYABUSA_CONFIG / "channel_eid_info.txt",
        HAYABUSA_CONFIG / "target_event_IDs.txt",
    ]
    for f in required:
        if not f.exists() or f.stat().st_size == 0:
            raise RuntimeError(f"hayabusa config missing/empty: {f}")

    run_id = str(uuid.uuid4())
    out_dir = PROJECT_ROOT / "outputs" / "csv" / "hayabusa_evtx" / run_id
    mkdirp(out_dir)

    profile = str(args.get("profile") or "verbose")
    iso_utc = bool(args.get("iso_utc", True))
    no_wizard = bool(args.get("no_wizard", True))
    clobber = bool(args.get("clobber", True))

    out_csv = out_dir / "timeline.csv"

    cmd = [str(HAYABUSA_BIN), "csv-timeline", "-d", str(evtx_dir), "-r", str(HAYABUSA_RULES), "-c", str(HAYABUSA_CONFIG), "-p", profile, "-o", str(out_csv)]
    if no_wizard:
        cmd.append("-w")
    if iso_utc:
        cmd.append("-O")
    if clobber:
        cmd.append("-C")

    rc, out, err = run_cmd(cmd, cwd=HAYABUSA_ROOT)
    audit_write(audit, "stdout", out)
    audit_write(audit, "stderr", err)

    if rc != 0:
        raise RuntimeError(f"hayabusa csv-timeline failed (rc={rc})")

    if not out_csv.is_file():
        raise RuntimeError(f"hayabusa did not create output file: {out_csv}")

    # Basic deterministic sanity check (header expected for verbose profile)
    head = out_csv.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not head or "Timestamp" not in head[0] or "RuleTitle" not in head[0]:
        raise RuntimeError(f"hayabusa output header unexpected: {head[0] if head else 'EMPTY'}")

    return {
        "run_id": run_id,
        "timeline_csv": str(out_csv),
        "evtx_dir": str(evtx_dir),
        "profile": profile
    }


def tool_read_json(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    max_bytes = int(args.get("max_bytes") or 65536)
    path = safe_resolve(args["path"])
    ensure_read_allowed(path)

    st = path.stat()
    if st.st_size > max_bytes:
        raise ValueError(f"file too large ({st.st_size} bytes) > max_bytes ({max_bytes})")

    doc = json.loads(path.read_text(encoding="utf-8"))
    ptr = args.get("json_pointer")
    value = json_pointer_get(doc, ptr)

    return {"path": str(path), "json_pointer": ptr, "value": value}

def tool_list_dir(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    path = safe_resolve(args["path"])
    ensure_read_allowed(path)
    if not path.is_dir():
        raise ValueError(f"not a directory: {path}")
    entries = sorted([p.name for p in path.iterdir()])
    return {"path": str(path), "entries": entries}

def tool_query_super_timeline(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    plaso_path = safe_resolve(args["plaso_file"])
    ensure_read_allowed(plaso_path)
    if not plaso_path.is_file():
        raise ValueError(f"plaso_file not found: {plaso_path}")

    start = args["start_time"]
    end = args["end_time"]
    fmt = args.get("output_format", "json")
    filt = args.get("artifact_filter")

    # Construct psort command
    cmd = [PSORT_BIN, "-z", "UTC"]
    if fmt == "json":
        cmd.extend(["-o", "json_line"])
    else:
        cmd.extend(["-o", "csv"])

    # Plaso filter syntax for time range
    # Use DATETIME() indicator as recommended by newer Plaso versions
    t_start = start.replace("T", " ").replace("Z", "")
    t_end = end.replace("T", " ").replace("Z", "")
    
    time_filter = f"timestamp > DATETIME('{t_start}') AND timestamp < DATETIME('{t_end}')"
    if filt:
        full_filter = f"({time_filter}) AND ({filt})"
    else:
        full_filter = time_filter

    # psort -o json_line requires -w (output file)
    run_id = str(uuid.uuid4())
    tmp_out = PROJECT_ROOT / f"tmp_psort_{run_id}.{fmt}"
    
    cmd.extend(["-w", str(tmp_out)])
    cmd.append(str(plaso_path))
    cmd.append(full_filter)

    rc, out, err = run_cmd(cmd, cwd=PROJECT_ROOT)
    
    # Read output file if it exists
    out_content = ""
    if tmp_out.exists():
        out_content = tmp_out.read_text(encoding="utf-8")
        tmp_out.unlink() # Cleanup

    audit_write(audit, "stdout", out_content)
    audit_write(audit, "stderr", err)

    if rc != 0:
        raise RuntimeError(f"psort failed (rc={rc}). Stderr: {err}")

    lines = out_content.strip().splitlines()
    if fmt == "json":
        preview = []
        for line in lines[:10]: # Return first 10 for safety/brevity
            try:
                preview.append(json.loads(line))
            except:
                continue
        return {
            "plaso_file": str(plaso_path),
            "window": {"start": start, "end": end},
            "count": len(lines),
            "events": preview
        }
    else:
        return {
            "plaso_file": str(plaso_path),
            "window": {"start": start, "end": end},
            "count": len(lines),
            "raw_csv_snippet": "\n".join(lines[:20]) # First 20 lines
        }

def dispatch_tool(name: str, arguments: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if name == "dfir.identify_evidence@1":
        return tool_identify_evidence(arguments, audit)
    if name == "dfir.auto_run@1":
        return tool_auto_run(arguments, audit)
    if name == "dfir.read_json@1":
        return tool_read_json(arguments, audit)
    if name == "dfir.list_dir@1":
        return tool_list_dir(arguments, audit)
    if name == "dfir.hayabusa_csv_timeline@1":
        return tool_hayabusa_csv_timeline(arguments, audit)
    if name == "dfir.query_super_timeline@1":
        return tool_query_super_timeline(arguments, audit)
    raise KeyError(f"unknown tool: {name}")

# ----------------------------
# JSON-RPC loop (MCP-shaped)
# ----------------------------
initialized = False

def handle(req: dict) -> dict:
    global initialized
    _id = req.get("id", None)
    method = req.get("method")
    params = req.get("params") or {}

    if method == "initialize":
        initialized = True
        # MCP-like initialize response
        return jsonrpc_ok(_id, {
            "serverInfo": {"name": "dfir-mcp", "version": "0.1.0"},
            "capabilities": {"tools": {}}
        })

    if method in ("shutdown", "exit"):
        return jsonrpc_ok(_id, {"ok": True})

    if not initialized:
        return jsonrpc_err(_id, -32002, "server not initialized (call initialize first)")

    if method == "tools/list":
        return jsonrpc_ok(_id, {"tools": TOOLS})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not tool_name:
            return jsonrpc_err(_id, -32602, "missing params.name")
        # audit envelope
        call_id = str(uuid.uuid4())
        paths = audit_paths(call_id)
        mkdirp(paths["base"])
        audit_write(paths, "request", json.dumps({"timestamp_utc": utc_now_z(), "rpc": req}, indent=2))

        try:
            audit_write(paths, "meta", json.dumps({
                "call_id": call_id,
                "timestamp_utc": utc_now_z(),
                "tool": tool_name
            }, indent=2))
            result = dispatch_tool(tool_name, arguments, paths)
            resp = jsonrpc_ok(_id, {"call_id": call_id, "result": result})
        except PermissionError as ex:
            resp = jsonrpc_err(_id, -32010, "permission denied", {"call_id": call_id, "detail": str(ex)})
        except Exception as ex:
            resp = jsonrpc_err(_id, -32020, "tool execution failed", {"call_id": call_id, "detail": str(ex)})

        audit_write(paths, "response", json.dumps(resp, indent=2))
        # ensure stdout/stderr exist
        if not paths["stdout"].exists():
            audit_write(paths, "stdout", "")
        if not paths["stderr"].exists():
            audit_write(paths, "stderr", "")
        return resp

    return jsonrpc_err(_id, -32601, f"method not found: {method}")

def main() -> int:
    mkdirp(AUDIT_ROOT)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as ex:
            write_line(jsonrpc_err(None, -32700, "parse error", {"detail": str(ex)}))
            continue
        write_line(handle(req))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

