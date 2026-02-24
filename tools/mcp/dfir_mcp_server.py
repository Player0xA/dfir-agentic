#!/usr/bin/env python3
import json
import os
import sys
import uuid
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, Optional, List, Tuple, Union

# ----------------------------
# Policy (v0.1)
# ----------------------------
PROJECT_ROOT = Path.cwd()
DEFAULT_MAX_BYTES = 100000 # 100KB "Ralph Wiggum" Guardrail

def get_case_dir() -> Optional[Path]:
    val = os.environ.get("DFIR_CASE_DIR")
    return Path(val).resolve() if val else None

DFIR_CASE_DIR = os.environ.get("DFIR_CASE_DIR")

ALLOWED_EVIDENCE_ROOTS = [
    PROJECT_ROOT.parent / "cases", # User external evidence (e.g., ../cases)
    PROJECT_ROOT / "cases",        # optional local
]

# Read-only roots for read_json/list_dir tools
ALLOWED_READ_ROOTS = [
    PROJECT_ROOT / "outputs",
    PROJECT_ROOT / "contracts",
]

if DFIR_CASE_DIR:
    CASE_PATH = Path(DFIR_CASE_DIR).resolve()
    ALLOWED_EVIDENCE_ROOTS.append(CASE_PATH)
    ALLOWED_READ_ROOTS.extend(ALLOWED_EVIDENCE_ROOTS) 
    ALLOWED_READ_ROOTS.append(CASE_PATH)
    AUDIT_ROOT = CASE_PATH / "toolruns" # Step 9: Auditable tool logs
else:
    ALLOWED_READ_ROOTS.extend(ALLOWED_EVIDENCE_ROOTS)
    AUDIT_ROOT = PROJECT_ROOT / "outputs" / "toolruns"


HAYABUSA_ROOT = PROJECT_ROOT / "tools" / "hayabusa"
HAYABUSA_BIN = HAYABUSA_ROOT / "bin" / "hayabusa"
HAYABUSA_RULES = HAYABUSA_ROOT / "rules"
HAYABUSA_CONFIG = HAYABUSA_RULES / "config"
PSORT_BIN = os.environ.get("PSORT_BIN", "psort.py")

# V20: Ensure user site-packages are visible (fixes macOS --user pathing issues)
try:
    import site
    if hasattr(site, "getusersitepackages"):
        user_site = site.getusersitepackages()
        if user_site and user_site not in sys.path and os.path.exists(user_site):
            sys.path.append(user_site)
except Exception:
    pass

# V19: Bridge to winforensics-mcp
WINFORENSICS_ROOT = PROJECT_ROOT / "tools" / "mcp" / "mcp-windows" / "winforensics-mcp"
if WINFORENSICS_ROOT.exists():
    sys.path.append(str(WINFORENSICS_ROOT))
    try:
        from winforensics_mcp.parsers import evtx_parser, registry_parser
        WINFORENSICS_AVAILABLE = True
    except ImportError:
        WINFORENSICS_AVAILABLE = False
else:
    WINFORENSICS_AVAILABLE = False


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
        "description": "Read a JSON file. Use 'evidence_ref' for investigation artifacts or 'path' for repo assets.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            },
                             "required": ["relpath"]
                        }
                    },
                    "required": ["case_ref", "evidence"]
                },
                "path": {"type": "string", "description": "Legacy/Internal fallback path"},
                "json_pointer": {"type": ["string", "null"]},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000}
            }
        }
    },
    {
        "name": "dfir.read_text@1",
        "description": "Read a text, log, or markdown file. Use 'evidence_ref' for investigation artifacts or 'path' for repo assets.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                },
                "path": {"type": "string", "description": "Legacy/Internal fallback path"},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000}
            }
        }
    },
    {
        "name": "dfir.query_findings@1",
        "description": "Surgically query the monolithic case_findings.json file.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                },
                "finding_id": {"type": "string"},
                "finding_ids": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
                "mitre_tactic": {"type": "string"},
                "limit": {"type": "integer", "default": 10}
            }
        }
    },
    {
        "name": "dfir.load_intake@1",
        "description": "Alias for read_json to read the intake.json or case.json file.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    },
    {
        "name": "dfir.hayabusa_csv_timeline@1",
        "description": "Run Hayabusa csv-timeline deterministically on an EVTX directory.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    },
    {
        "name": "dfir.list_dir@1",
        "description": "List directory entries. Use 'evidence_ref' for investigation artifacts or 'path' for repo assets.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                },
                "path": {"type": "string", "description": "Legacy/Internal fallback path"}
            }
        }
    },
    {
        "name": "dfir.query_super_timeline@1",
        "description": "Query a Plaso .plaso storage file with a structured filter.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref", "start_time", "end_time"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {
                            "type": "string",
                            "description": "Path to case.json or 'CASE' for active case"
                        },
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                },
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
                "search_term": {"type": "string"},
                "event_ids": {"type": "array", "items": {"type": "integer"}}
            }
        }
    },
    {
        "name": "dfir.load_skill@1",
        "description": "Load detailed instructions for a specific forensic skill. Returns markdown.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["skill_name"],
            "properties": {
                "skill_name": {"type": "string", "minLength": 1, "description": "e.g., 'analyzing-timeline'"},
                "file_name": {"type": "string", "description": "Optional specific file to load (e.g., 'psort_cheatsheet.md')"}
            }
        }
    },
    {
        "name": "dfir.update_case_notes@1",
        "description": "Log structured investigation claims. Every statement must be an OBSERVATION, DERIVED, HYPOTHESIS, ASSESSMENT, GAP, or UNKNOWN.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["claims", "next_steps"],
            "properties": {
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "claim_id": { "type": "string" },
                            "type": { "type": "string", "enum": ["OBSERVATION", "DERIVED", "HYPOTHESIS", "ASSESSMENT", "GAP", "UNKNOWN"] },
                            "statement": { "type": "string" },
                            "evidence_refs": { "type": "array", "items": { "type": "string" } },
                            "confidence": { "type": "string", "enum": ["High", "Medium", "Low", "N/A"] },
                            "impact": { "type": "string", "enum": ["Low", "Medium", "High"], "description": "Used specifically for GAP types." },
                            "validation_plan": { "type": "string" },
                            "status": { "type": "string", "enum": ["Open", "Supported", "Confirmed", "Refuted"] }
                        },
                        "required": ["claim_id", "type", "statement", "status"]
                    }
                },
                "next_steps": { "type": "array", "items": { "type": "string" } }
            }
        }
    },
    {
        "name": "dfir.correlate_pivot@1",
        "description": "Deterministic correlation module: LogonId -> Auth Logs, PID -> Process Creation, etc.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["pivot_type", "pivot_value"],
            "properties": {
                "pivot_type": { "type": "string", "enum": ["LogonId", "PID", "SrcIP"] },
                "pivot_value": { "type": "string" }
            }
        }
    },
    {
        "name": "dfir.pivot_ladder@1",
        "description": "Automated fallback engine: if a keyword search fails, generate a metadata-based search plan.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["failed_search_term", "plaso_file"],
            "properties": {
                "failed_search_term": { "type": "string" },
                "plaso_file": { "type": "string" }
            }
        }
    },
    {
        "name": "dfir.load_case_context@1",
        "description": "Load the deterministic case context bundle: intake summary, top findings, and pivot pointers.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["case_dir"],
            "properties": {
                "case_dir": {"type": "string", "description": "The path to the case directory or 'CASE'"}
            }
        }
    },
    {
        "name": "dfir.build_query_plan@1",
        "description": "Formalize an investigation query plan. Outputs a plan object.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["primary_window", "pivots_to_search"],
            "properties": {
                "primary_window": {"type": "string", "description": "e.g., '2026-02-11T20:00:00Z to 24:00:00Z'"},
                "secondary_window": {"type": "string"},
                "pivots_to_search": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "max_queries_budget": {"type": "integer"}
            }
        }
    },
    {
        "name": "dfir.evtx_search@1",
        "description": "Surgical EVTX search: query a specific .evtx file for Event IDs or keywords.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {"type": "string", "description": "Absolute path to case.json"},
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string", "description": "Relative path within the root (e.g. evtx/Logs/Security.evtx)"}
                            }
                        }
                    }
                },
                "event_ids": {"type": "array", "items": {"type": "integer"}},
                "contains": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 20}
            }
        }
    },
    {
        "name": "dfir.registry_get_persistence@1",
        "description": "Extract common persistence keys from a registry hive.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence_ref"],
            "properties": {
                "evidence_ref": {
                    "type": "object",
                    "required": ["case_ref", "evidence"],
                    "properties": {
                        "case_ref": {"type": "string"},
                        "evidence": {
                            "type": "object",
                            "required": ["relpath"],
                            "properties": {
                                "root": {"type": "string", "enum": ["staged", "original", "case"], "default": "staged"},
                                "relpath": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    }
]

# ----------------------------
# Helpers
# ----------------------------
def symbolize_path(path: str | Path) -> str:
    """Replaces the absolute Case Root with CASE:// for AI context."""
    p_str = str(path)
    case_dir = get_case_dir()
    if case_dir:
        abs_case = str(case_dir.resolve())
        if p_str.startswith(abs_case):
            # Resolve leading slash to ensure CASE://path instead of CASE:///path
            rel = p_str.replace(abs_case, "").lstrip("/")
            return f"CASE://{rel}"
    return p_str


def get_evidence_path_from_ref(evidence_ref: Any, audit_paths: Dict[str, Path], default_root: str = "staged") -> Path:
    """Authoritative EvidenceRef -> Absolute Path solver with rich auditing and legacy support."""
    if isinstance(evidence_ref, str):
        # Legacy support: resolve via safe/resolve_evidence
        return resolve_evidence(evidence_ref)
        
    if not isinstance(evidence_ref, dict):
        raise ValueError(f"Invalid EvidenceRef type: {type(evidence_ref)}")

    case_ref = evidence_ref.get("case_ref")
    evidence = evidence_ref.get("evidence", {})
    root = evidence.get("root", default_root)
    relpath = evidence.get("relpath")
    
    if not relpath and "path" in evidence_ref:
        # Alternative schema support
        return resolve_evidence(evidence_ref["path"])
        
    if not relpath:
        raise ValueError("EvidenceRef missing 'relpath'")
    
    # 1. Resolve path
    abs_path = resolve_evidence_path(case_ref, root, relpath)

    # Step 9: Traversal Control (Reject paths outside case_root)
    if str(case_ref).upper() == "CASE" or str(case_ref).startswith("CASE://"):
        case_dir = get_case_dir()
        case_root = case_dir.resolve() if case_dir else None
    else:
        case_root = Path(case_ref).parent.resolve()
    
    if case_root:
        try:
            abs_path.relative_to(case_root)
        except ValueError:
            # Check if it's in original but outside root? No, case_root should be the parent of case.json
            # and all evidence/original, evidence/staged should be subdirs.
            # If it's malicious, catch it.
            raise PermissionError(f"Traversal Guard: Path escapes case root: {abs_path}")

    # 2. Rich Audit Logging (Step 6)
    audit_data = {
        "resolved_path": str(abs_path),
        "evidence_ref": evidence_ref,
        "exists": abs_path.exists(),
        "timestamp_utc": utc_now_z()
    }
    
    # 3. Step 9: Strict Mode Hash Verification
    if abs_path.exists() and root in ("original", "staged"):
        try:
            manifest_path = case_root / "manifests" / f"{root}.manifest.json"
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text())
                file_info = next((f for f in manifest.get("files", []) if f["relpath"] == relpath), None)
                if file_info:
                    expected_hash = file_info["sha256"]
                    audit_data["manifest_sha256"] = expected_hash
                    
                    # Compute actual hash for verification (Strict Mode)
                    actual_hash = hashlib.sha256()
                    with open(abs_path, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            actual_hash.update(chunk)
                    
                    if actual_hash.hexdigest() != expected_hash:
                        raise RuntimeError(f"INTEGRITY FAILURE: Hash mismatch for {relpath}. Expected {expected_hash}, got {actual_hash.hexdigest()}")
                    
                    audit_data["integrity_check"] = "PASS"
        except (PermissionError, RuntimeError):
            raise
        except Exception as e:
            audit_data["integrity_check"] = f"WARN: {str(e)}"

    audit_write(audit_paths, "evidence_audit", json.dumps(audit_data, indent=2))
    return abs_path

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

def resolve_project_path(p: str) -> Path:
    """Authoritative resolution for repo assets (skills, tools, configs)."""
    path = Path(p)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    else:
        path = path.resolve()
    return path

def resolve_evidence_path(case_ref: str | Path, root_name: str, relpath: str) -> Path:
    """Authoritative resolution for forensic evidence via case.json."""
    if str(case_ref).upper() == "CASE" or str(case_ref).startswith("CASE://"):
        case_dir = get_case_dir()
        if not case_dir:
             raise ValueError("Symbolic 'CASE' reference used but DFIR_CASE_DIR is not set.")
        case_path = case_dir / "case.json"
        if not case_path.exists():
            case_path = case_dir / "intake.json"
    else:
        case_path = Path(case_ref).resolve()

    if not case_path.exists():
        # Fallback for Phase 28 transition: if case_ref is missing, try DFIR_CASE_DIR
        case_dir = get_case_dir()
        if case_dir:
            # If we used CASE alias, case_dir / relpath might be wrong if it's staged evidence
            # But here we are resolving from case.json, so let's continue.
            pass
        else:
            raise FileNotFoundError(f"Case metadata not found: {case_path}")
    
    with open(case_path, 'r') as f:
        case_data = json.load(f)
        
    if root_name == "case":
        base = case_path.parent
    else:
        evidence_roots = case_data.get("evidence_roots", {})
        base = Path(evidence_roots.get(root_name, evidence_roots.get("staged", case_data.get("case_root"))))
    
    return (base / relpath).resolve()

# Legacy aliases for Phase 28 transition
def resolve_internal(p: str) -> Path:
    return resolve_project_path(p)

def resolve_evidence(p: str) -> Path:
    """Bridge for legacy string-only paths during transition."""
    case_dir = get_case_dir()
    
    # Phase 36: Symbolic URI Support
    if p.upper().startswith("CASE://"):
        rel = p[7:].lstrip("/")
        if case_dir:
            return (case_dir / rel).resolve()
    elif p.upper().startswith("CASE:"):
        rel = p[5:].lstrip("/")
        if case_dir:
            return (case_dir / rel).resolve()

    path = Path(p)
    if not path.is_absolute() and case_dir:
        return (case_dir / path).resolve()
    
    # V21/V25: Hallucination Healer (Heuristic Remapper for absolute junk)
    if not path.exists():
        parts = Path(p).parts
        markers = {"cases", "outputs", "intake", "evtx", "Logs", "data"}
        bases = [PROJECT_ROOT, PROJECT_ROOT.parent]
        if case_dir:
            bases.append(case_dir.parent)
        
        for i, part in enumerate(parts):
            if part in markers:
                tail = Path(*parts[i:])
                for base in bases:
                    candidate = (base / tail).resolve()
                    if candidate.exists():
                        return candidate
    return path.resolve()

def safe_resolve(p: str) -> Path:
    """Legacy alias, defaults to evidence resolution as it's the highest risk."""
    return resolve_evidence(p)

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
    # V29: Dynamically allow reading from PROJECT_ROOT or current CASE_ROOT
    roots = ALLOWED_READ_ROOTS[:]
    case_dir = get_case_dir()
    if case_dir:
        roots.append(case_dir)
        
    if not under_any_root(path, roots):
        # Final fallback: if it's within PROJECT_ROOT, allow it
        if not under_any_root(path, [PROJECT_ROOT, PROJECT_ROOT.parent]):
            raise PermissionError(f"read denied: path outside allowed roots: {path}")

def ensure_evidence_allowed(path: Path) -> None:
    roots = ALLOWED_EVIDENCE_ROOTS[:]
    case_dir = get_case_dir()
    if case_dir:
        roots.append(case_dir)
        
    if not under_any_root(path, roots):
        if not under_any_root(path, [PROJECT_ROOT.parent / "cases"]):
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
        "evidence_audit": base / "evidence_audit.json"
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
def tool_load_case_context(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    case_dir = safe_resolve(args["case_dir"])
    ensure_read_allowed(case_dir)
    
    context = {}
    
    # Load Summary
    summary_path = case_dir / "case_summary.md"
    if summary_path.exists():
        context["case_summary"] = summary_path.read_text(encoding="utf-8")
        
    # Load Top Findings (Critical)
    findings_path = case_dir / "case_findings.json"
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            criticals = [f for f in findings if f.get("severity") == "critical"]
            context["top_critical_findings"] = criticals[:5] # Max 5
        except Exception as e:
            context["top_critical_findings_error"] = str(e)
            
    # Load Pointers (Plaso Timeline)
    plaso_files = list(case_dir.glob("*.plaso"))
    if plaso_files:
        context["available_timelines"] = [symbolize_path(p) for p in plaso_files]
        
    return context

def tool_build_query_plan(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    return {
        "status": "APPROVED",
        "plan": args,
        "note": "Plan formalized. You may now execute read-only queries in batches according to this plan."
    }

def tool_validate_deliverable(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    import jsonschema
    import json
    schema_path = PROJECT_ROOT / "contracts" / "root_cause.schema.json"
    if not schema_path.exists():
        return {"status": "ERROR", "message": "Schema file not found on disk."}
    
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        rca = args["root_cause_analysis"]
        jsonschema.validate(instance=rca, schema=schema)
        return {"status": "SUCCESS", "message": "root_cause_analysis is valid and ready for finalization."}
    except jsonschema.exceptions.ValidationError as ve:
        # V17: Consistent error feedback with orchestrator
        msg = ve.message
        if "required" in msg.lower():
            msg = f"RCA Schema Validation Failed: {msg}. Ensure 'summary', 'root_cause', 'confidence', 'claims', 'unknowns', and 'assessment' are ALL present."
        raise ValueError(msg)
    except Exception as e:
        raise ValueError(f"Validation Error: {str(e)}")

def tool_correlate_pivot(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    ptype = args["pivot_type"]
    pval = args["pivot_value"]
    
    correlations = {
        "LogonId": f"Pivoting LogonId {pval} to Security Event IDs 4624 (Logon), 4634 (Logoff), and 4672 (Admin Logon).",
        "SubjectLogonId": f"Pivoting SubjectLogonId {pval} to Security Event IDs 4624, 4634, 4672, and 4688 (Process Creation).",
        "PID": f"Pivoting PID {pval} to Security Event ID 4688 (Process Creation) and Sysmon Event ID 3 (Network Connection).",
        "ClientProcessId": f"Pivoting ClientProcessId {pval} to Security Event ID 4688 and Sysmon activity.",
        "SrcIP": f"Pivoting SrcIP {pval} to Firewall logs, SMB activity (Event ID 5140), and RDP authentication events (Event ID 4624/4778)."
    }
    
    return {
        "pivot": ptype,
        "value": pval,
        "suggested_query": correlations.get(ptype, "No deterministic rule found."),
        "note": "Execute query_super_timeline with the suggested event IDs and this value as a search term or in specific fields."
    }

def tool_pivot_ladder(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    failed_term = args["failed_search_term"]
    
    # Deterministic fallback plan
    return {
        "failed_term": failed_term,
        "fallback_plan": [
            "1. Search by Event ID range (e.g. 4624, 4625 for auth) around the known time window.",
            "2. Expand your search window by +/- 5 minutes to account for clock drift.",
            "3. Search by Provider GUID or Channel (e.g. Security, System) if metadata is known.",
            "4. Search for related PIDs or ParentPIDs if found in other artifacts."
        ],
        "note": "Keyword search failed. Broaden your scope to metadata and time-window expansion to avoid budget waste."
    }

def tool_identify_evidence(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Phase 25: Evidence Resolution
    raw_path = resolve_evidence(args["path"])
    ensure_evidence_allowed(raw_path)

    cmd = [str(PROJECT_ROOT / "tools/intake/identify_evidence.py"), str(raw_path)]
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
    
    intake_data = json.loads(intake_abs.read_text(encoding="utf-8"))
    
    # Validate (V30 Compatibility)
    if "case_id" in intake_data:
        v_schema = str(PROJECT_ROOT / "contracts/case.schema.json")
    else:
        v_schema = str(PROJECT_ROOT / "contracts/intake.schema.json")

    # Validate intake (hard gate)
    vcmd = [
        str(PROJECT_ROOT / "tools/contracts/validate_intake.py"),
        v_schema,
        str(intake_abs),
    ]
    rc2, out2, err2 = run_cmd(vcmd, cwd=PROJECT_ROOT)
    audit_write(audit, "stdout", (audit["stdout"].read_text(encoding="utf-8") if audit["stdout"].exists() else "") + out2)
    audit_write(audit, "stderr", (audit["stderr"].read_text(encoding="utf-8") if audit["stderr"].exists() else "") + err2)
    if rc2 != 0:
        raise RuntimeError(f"metadata validation failed against {v_schema}")

    return {"intake_json": str(intake_abs)}

def tool_auto_run(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Phase 25: Internal Resolution (outputs/contracts)
    intake_path = resolve_internal(args["intake_json"])
    ensure_read_allowed(intake_path)

    # For safety, ensure the metadata itself refers to evidence under allowed evidence roots.
    try:
        intake_doc = json.loads(intake_path.read_text(encoding="utf-8"))
        if "case_id" in intake_doc:
            # V30 Check
            staged = [e for e in intake_doc.get("evidence", []) if e.get("root") == "staged"]
            if staged:
                ev_path = Path(intake_doc["evidence_roots"]["staged"]) / staged[0]["relpath"]
            else:
                ev_path = Path(intake_doc["evidence_roots"]["original"]) / intake_doc["evidence"][0]["relpath"]
        else:
            # Legacy Check
            ev = intake_doc["inputs"]["paths"][0]
            ev_path = resolve_evidence(ev)
            
        ensure_evidence_allowed(ev_path)
    except Exception as ex:
        raise PermissionError(f"metadata evidence root check failed: {ex}")

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
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    evtx_dir = get_evidence_path_from_ref(ref, audit)
    ensure_read_allowed(evtx_dir)
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
    if DFIR_CASE_DIR:
        out_dir = Path(DFIR_CASE_DIR) / "hayabusa_evtx" / run_id
    else:
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
    # Synchronized 100KB Guardrail
    max_bytes = int(args.get("max_bytes") or DEFAULT_MAX_BYTES)
    if max_bytes > DEFAULT_MAX_BYTES:
        max_bytes = DEFAULT_MAX_BYTES

    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit, default_root="case")
    ensure_read_allowed(path)

    st = path.stat()
    if st.st_size > max_bytes:
        raise ValueError(f"file too large ({st.st_size} bytes) > max_bytes ({max_bytes}). Use surgical query tools for large files.")

    doc = json.loads(path.read_text(encoding="utf-8"))
    ptr = args.get("json_pointer")
    value = json_pointer_get(doc, ptr)

    return {"path": symbolize_path(path), "json_pointer": ptr, "value": value}


def tool_read_text(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Synchronized 100KB Guardrail
    max_bytes = int(args.get("max_bytes") or DEFAULT_MAX_BYTES)
    if max_bytes > DEFAULT_MAX_BYTES:
        max_bytes = DEFAULT_MAX_BYTES

    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit, default_root="case")
    ensure_read_allowed(path)

    st = path.stat()
    if st.st_size > max_bytes:
        raise ValueError(f"read_text failed: file too large ({st.st_size} bytes) > max_bytes ({max_bytes}). Treat large logs as data sources, not context.")

    content = path.read_text(encoding="utf-8")
    return {"path": symbolize_path(path), "value": content}




def tool_query_findings(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit, default_root="case")
    ensure_read_allowed(path)
    
    if not path.is_file():
        raise ValueError(f"file not found: {path}")

    # Load full file - this is done in memory by the TOOL, keeping it out of LLM context
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = doc.get("findings", [])
    
    finding_id = args.get("finding_id")
    finding_ids = args.get("finding_ids")
    severity = args.get("severity")
    tactic = args.get("mitre_tactic")
    limit = int(args.get("limit") or 10)

    filtered = []
    
    # V37 Hex Normalization for ID search
    target_ids = set()
    if finding_id:
        target_ids.add(finding_id)
        if finding_id.startswith("0x"):
            try:
                val = int(finding_id[2:], 16)
                target_ids.add(finding_id.lower())
                target_ids.add(finding_id.upper())
                target_ids.add(f"0x{val:08x}")
                target_ids.add(f"0x{val:08X}")
                target_ids.add(f"0x{val:016x}")
                target_ids.add(f"0x{val:016X}")
            except ValueError:
                pass

    for f in findings:
        fid = f.get("finding_id")
        
        # Filter by ID (Robust)
        if target_ids and fid not in target_ids:
            continue
        
        # Filter by Batch IDs
        if finding_ids and fid not in finding_ids:
            continue
        
        # Filter by Severity
        if severity and (f.get("severity") or "informational").lower() != severity.lower():
            continue
            
        # Filter by Tactic
        if tactic:
            tags = f.get("tactic_tags") or f.get("mitre_tags") or []
            if not any(tactic.lower() in t.lower() for t in tags):
                continue
                
        filtered.append(f)
        if len(filtered) >= limit:
            break
            
    return {
        "path": symbolize_path(path),
        "total_matched": len(filtered),
        "results": filtered,
        "note": "Use finding_id for surgical extraction of a single high-fidelity finding."
    }

def tool_list_dir(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit)
    ensure_read_allowed(path)
    if not path.is_dir():
        raise ValueError(f"not a directory: {path}")
    entries = sorted([p.name for p in path.iterdir()])
    return {
        "path": symbolize_path(path),
        "entries": entries
    }

def tool_query_super_timeline(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path") or args.get("plaso_file")
    plaso_path = get_evidence_path_from_ref(ref, audit, default_root="case")
    ensure_read_allowed(plaso_path)
    if not plaso_path.is_file():
        raise ValueError(f"plaso_file not found: {plaso_path}")

    start = args["start_time"]
    end = args["end_time"]
    fmt = args.get("output_format", "json")
    
    search = args.get("search_term")
    e_ids = args.get("event_ids")

    # psort -o json_line requires -w (output file)
    run_id = str(uuid.uuid4())
    if DFIR_CASE_DIR:
        tmp_out = Path(DFIR_CASE_DIR) / f"tmp_psort_{run_id}.{fmt}"
    else:
        tmp_out = PROJECT_ROOT / f"tmp_psort_{run_id}.{fmt}"

    # Construct psort command
    # Ordering: binary, output options, storage file, filter
    cmd = [PSORT_BIN, "-o", "json_line", "-w", str(tmp_out), "--output_time_zone", "UTC"]

    # Plaso filter syntax for time range
    # Standardize on space-delimited (YYYY-MM-DD hh:mm:ss.######) and single quotes
    t_start = start.replace("T", " ").replace("Z", "").strip()
    t_end = end.replace("T", " ").replace("Z", "").strip()
    
    time_filter = f"date > '{t_start}' AND date < '{t_end}'"
    
    # Backend Abstraction: Constructing filter programmatically
    struct_parts = []
    if search:
        # V17 Robust Hex Normalization: Plaso contains filter is literal.
        # Windows logs use 8-char or 16-char zero-padding for IDs.
        if search.startswith("0x"):
            try:
                hex_val = search[2:]
                val = int(hex_val, 16)
                
                # Generate variants
                variants = set()
                variants.add(search.lower())
                variants.add(search.upper())
                variants.add(f"0x{val:08x}")
                variants.add(f"0x{val:08X}")
                variants.add(f"0x{val:016x}")
                variants.add(f"0x{val:016X}")
                
                # Build OR chain
                or_parts = [f"message contains '{v}'" for v in sorted(list(variants))]
                struct_parts.append(f"({' OR '.join(or_parts)})")
            except ValueError:
                struct_parts.append(f"message contains '{search}'")
        else:
            struct_parts.append(f"message contains '{search}'")
    if e_ids:
        # Note: Older Plaso SQL-like syntax rejects IN. Expand to OR chain.
        ids_parts = [f"event_identifier == {i}" for i in e_ids]
        struct_parts.append(f"({' OR '.join(ids_parts)})")
    
    if struct_parts:
        full_filter = f"({time_filter}) AND ({' AND '.join(struct_parts)})"
    else:
        full_filter = time_filter

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
        raise RuntimeError(f"psort failed (rc={rc}). filter='{full_filter}' Stderr: {err}")

    lines = out_content.strip().splitlines()
    if fmt == "json":
        from collections import Counter
        preview = []
        pivots = {"event_ids": Counter(), "users": Counter(), "pids": Counter()}
        
        for line in lines:
            try:
                evt = json.loads(line)
                if len(preview) < 10:
                    preview.append(evt)
                    
                # Pivot extraction
                if "event_identifier" in evt and evt["event_identifier"] is not None:
                    pivots["event_ids"][evt["event_identifier"]] += 1
                if "username" in evt and evt["username"] not in ("-", "", "N/A", None):
                    pivots["users"][evt["username"]] += 1
                if "pid" in evt and evt["pid"] is not None:
                    pivots["pids"][evt["pid"]] += 1
            except:
                continue
                
        pivot_summary = {
            "top_event_ids": dict(pivots["event_ids"].most_common(5)),
            "top_users": dict(pivots["users"].most_common(5)),
            "top_pids": dict(pivots["pids"].most_common(5))
        }

        return {
            "plaso_file": symbolize_path(plaso_path),
            "window": {"start": start, "end": end},
            "count": len(lines),
            "events": preview,
            "auto_pivot_extraction": pivot_summary
        }
    else:
        return {
            "plaso_file": symbolize_path(plaso_path),
            "window": {"start": start, "end": end},
            "count": len(lines),
            "raw_csv_snippet": "\n".join(lines[:20]) # First 20 lines
        }

def tool_load_skill(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    skill_name = args["skill_name"]
    file_name = args.get("file_name") or "SKILL.md"
    
    # Path validation: must be in .skills/
    skill_dir = PROJECT_ROOT / ".skills" / skill_name
    target_file = (skill_dir / file_name).resolve()
    
    # Security check: must be inside .skills directory
    skills_root = (PROJECT_ROOT / ".skills").resolve()
    try:
        target_file.relative_to(skills_root)
    except ValueError:
        raise PermissionError(f"Access denied: {target_file} is outside .skills root")

    if not target_file.is_file():
        raise FileNotFoundError(f"Skill file not found: {target_file}")

    content = target_file.read_text(encoding="utf-8")
    
    # If reading SKILL.md, strip YAML frontmatter
    if file_name == "SKILL.md":
        import re
        # Match content between triple-dashes at the start of the file
        content = re.sub(r'^---\s*\n.*?\n---\s*\n', '', content, flags=re.DOTALL)

    return {
        "skill_name": skill_name,
        "file_name": file_name,
        "content": content.strip()
    }

def tool_update_case_notes(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if not DFIR_CASE_DIR:
        raise RuntimeError("DFIR_CASE_DIR not set; cannot update case notes.")
    
    case_path = Path(DFIR_CASE_DIR)
    progress_file = case_path / "progress.md"
    
    claims = args.get("claims", [])
    next_steps = args.get("next_steps", [])
    
    timestamp = utc_now_z()
    
    # Format entry
    entry = f"\n## {timestamp}\n"
    for c in claims:
        cid = c.get("claim_id", "UNC-ID")
        ctype = c.get("type", "UNKNOWN")
        stmt = c.get("statement", "")
        refs = ", ".join(c.get("evidence_refs", []))
        conf = c.get("confidence", "N/A")
        impact = c.get("impact", "")
        status = c.get("status", "Open")
        
        if ctype == "GAP":
             entry += f"- **[GAP]** ({cid}): {stmt} | Impact: {impact} | Status: {status}\n"
        else:
             entry += f"- **[{ctype}]** ({cid}): {stmt} | Refs: `{refs}` | Conf: {conf} | Status: {status}\n"
        if c.get("validation_plan"):
            entry += f"  > Validation: {c['validation_plan']}\n"
            
    if next_steps:
        entry += "\n### Next Steps\n"
        for ns in next_steps:
            entry += f"- {ns}\n"
    
    # Append to file
    with open(progress_file, "a", encoding="utf-8") as f:
        f.write(entry)
        
    return {"path": str(progress_file), "status": "updated"}

# Already handled by top helper

def tool_evtx_search(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if not WINFORENSICS_AVAILABLE:
        raise RuntimeError("winforensics-mcp parsers not available.")
    
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit)
    ensure_read_allowed(path)
    
    return evtx_parser.get_evtx_events(
        evtx_path=path, 
        event_ids=args.get("event_ids"), 
        contains=args.get("contains"), 
        limit=int(args.get("limit") or 20)
    )

def tool_evtx_security_search(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if not WINFORENSICS_AVAILABLE:
        raise RuntimeError("winforensics-mcp parsers not available.")
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit)
    ensure_read_allowed(path)
    return evtx_parser.search_security_events(evtx_path=path, event_type=args["event_type"], limit=int(args.get("limit") or 20))

def tool_registry_get_persistence(args: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if not WINFORENSICS_AVAILABLE:
        raise RuntimeError("winforensics-mcp parsers not available.")
        
    # Phase 29: Uniform EvidenceRef Contract
    ref = args.get("evidence_ref") or args.get("path")
    path = get_evidence_path_from_ref(ref, audit)
    ensure_read_allowed(path)
    
    hive_name = path.name.upper()
    results = []
    if "SOFTWARE" in hive_name or "NTUSER" in hive_name:
        results.extend(registry_parser.get_run_keys(path))
    elif "SYSTEM" in hive_name:
        results.extend(registry_parser.get_services(path))
    return {"hive": str(path), "total": len(results), "persistence_entries": results}

def dispatch_tool(name: str, arguments: Dict[str, Any], audit: Dict[str, Path]) -> Dict[str, Any]:
    if name == "dfir.identify_evidence@1":
        return tool_identify_evidence(arguments, audit)
    if name == "dfir.auto_run@1":
        return tool_auto_run(arguments, audit)
    if name in ("dfir.read_json@1", "dfir.load_intake@1"):
        return tool_read_json(arguments, audit)
    if name == "dfir.read_text@1":
        return tool_read_text(arguments, audit)
    if name == "dfir.query_findings@1":
        return tool_query_findings(arguments, audit)
    if name == "dfir.list_dir@1":
        return tool_list_dir(arguments, audit)
    if name == "dfir.hayabusa_csv_timeline@1":
        return tool_hayabusa_csv_timeline(arguments, audit)
    if name == "dfir.query_super_timeline@1":
        return tool_query_super_timeline(arguments, audit)
    if name == "dfir.query_findings@1":
        return tool_query_findings(arguments, audit)
    if name == "dfir.load_skill@1":
        return tool_load_skill(arguments, audit)
    if name == "dfir.load_case_context@1":
        return tool_load_case_context(arguments, audit)
    if name == "dfir.build_query_plan@1":
        return tool_build_query_plan(arguments, audit)
    if name == "dfir.validate_deliverable@1":
        return tool_validate_deliverable(arguments, audit)
    if name == "dfir.correlate_pivot@1":
        return tool_correlate_pivot(arguments, audit)
    if name == "dfir.pivot_ladder@1":
        return tool_pivot_ladder(arguments, audit)
    if name == "dfir.update_case_notes@1":
        return tool_update_case_notes(arguments, audit)
    if name == "dfir.evtx_search@1":
        return tool_evtx_search(arguments, audit)
    if name == "dfir.evtx_security_search@1":
        return tool_evtx_security_search(arguments, audit)
    if name == "dfir.registry_get_persistence@1":
        return tool_registry_get_persistence(arguments, audit)
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

