#!/usr/bin/env python3
"""
Step 5.0 — DeepSeek Orchestrator (commentary-only)

Hard rules:
- Only reads through MCP tools (dfir.read_json@1 etc)
- Only summarizes triage/findings metadata, never raw logs
- Writes auditable AI artifacts under outputs/ai/orchestrator/<intake_id>/<ai_id>/

Env:
- DEEPSEEK_API_KEY required
Optional:
- DEEPSEEK_MODEL (default: deepseek-chat)
- DEEPSEEK_BASE_URL (default: https://api.deepseek.com)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import uuid
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import concurrent.futures

PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
# V7: Robust Path Hydration
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def _get_mcp_python(base_dir: Path) -> str:
    """Phase 46: Dynamically resolve the virtual environment python path."""
    for venv in [".venv", "venv"]:
        # Mac/Linux
        cand = base_dir / venv / "bin" / "python3"
        if cand.exists():
            return str(cand)
        # Windows fallback (just in case they run it natively)
        cand_win = base_dir / venv / "Scripts" / "python.exe"
        if cand_win.exists():
            return str(cand_win)
    return "python3" # Fallback to system

MCP_SERVERS = {
    "dfir": {
        "command": ["python3", "-u", str(PROJECT_ROOT / "tools/mcp/dfir_mcp_server.py")],
        "cwd": PROJECT_ROOT
    },
    "win": {
        "command": [
            _get_mcp_python(PROJECT_ROOT / "tools/mcp/mcp-windows/winforensics-mcp"),
            "-u",
            "-m",
            "winforensics_mcp.server"
        ],
        "cwd": PROJECT_ROOT / "tools/mcp/mcp-windows/winforensics-mcp"
    },
    "mem": {
        "command": [
            _get_mcp_python(PROJECT_ROOT / "tools/mcp/memory/mem_forensics-mcp"),
            "-u",
            "-m",
            "mem_forensics_mcp.server"
        ],
        "cwd": PROJECT_ROOT / "tools/mcp/memory/mem_forensics-mcp"
    }
}

# Phase 35: Full Epistemic Protocol
EPISTEMIC_SIGNALS = {
    "HYPOTHESIS": [
        "attacker", "compromised", "compromise", "malicious", "lateral movement", "privilege escalation",
        "likely", "suggests", "indicates", "caused", "led to", "to hide", "because", "due to"
    ],
    "GAP": ["missing", "logging gap", "not found", "limitations", "unparsed", "missing evidence"]
}

def auto_correct_epistemic_claims(tool_args: dict):
    """Programmatically enforces the V35 Epistemic Protocol."""
    claims = tool_args.get("claims", [])
    for c in claims:
        stmt = c.get("statement", "").lower()
        ctype = c.get("type", "UNKNOWN")
        
        # 1. Structural/Keyword Detection (Upgrade to HYPOTHESIS)
        if any(k in stmt for k in EPISTEMIC_SIGNALS["HYPOTHESIS"]) and ctype != "HYPOTHESIS" and ctype != "ASSESSMENT":
            print(f"[*] Epistemic Leveling: Upgraded '{c.get('claim_id')}' to HYPOTHESIS (Signal detected).")
            c["type"] = "HYPOTHESIS"
            ctype = "HYPOTHESIS"

        # 2. GAP Detection
        if any(k in stmt for k in EPISTEMIC_SIGNALS["GAP"]) and ctype != "GAP":
             print(f"[*] Epistemic Leveling: Tagged '{c.get('claim_id')}' as GAP.")
             c["type"] = "GAP"
             ctype = "GAP"

        # 3. Auto-Metadata Defaults (V35 Table)
        if ctype == "OBSERVATION":
            c.setdefault("confidence", "High")
            c.setdefault("status", "Open")
        elif ctype == "DERIVED":
            c.setdefault("confidence", "High")
            c.setdefault("status", "Open")
        elif ctype == "HYPOTHESIS":
            c.setdefault("confidence", "Medium")
            c.setdefault("status", "Open")
        elif ctype == "ASSESSMENT":
            c.setdefault("confidence", "Medium")
            c.setdefault("status", "Open")
        elif ctype == "GAP":
            c.setdefault("impact", "Medium")
            c.setdefault("status", "Open")
            # Clear confidence for GAPs as per schema
            if "confidence" in c: del c["confidence"]

AUTO_APPROVE_TOOLS = [
    "dfir.read_json@1",
    "dfir.read_text@1",
    "dfir.query_findings@1",
    "dfir.list_dir@1",
    "dfir.load_skill@1",
    "dfir.query_super_timeline@1"
]

def validate_arguments(name: str, arguments: dict, mcp_tools: list[dict]) -> Optional[str]:
    """
    Validates arguments against the tool's inputSchema using jsonschema if available.
    Returns None if valid, or an error string if invalid.
    """
    tool_def = next((t for t in mcp_tools if t["name"] == name), None)
    if not tool_def:
        return f"Tool '{name}' not found in registry."
    
    schema = tool_def.get("inputSchema")
    if not schema:
        return None # No schema to validate against
        
    try:
        import jsonschema
        jsonschema.validate(instance=arguments, schema=schema)
        return None
    except ImportError:
        # Fallback: very basic check for required fields if jsonschema is missing
        required = schema.get("required", [])
        missing = [r for r in required if r not in arguments]
        if missing:
            return f"Missing required arguments: {', '.join(missing)}"
        return None
    except Exception as e:
        return f"Validation error for {name}: {str(e)}"

def compact_history(history: list[dict]):
    """
    Finds if the assistant just called 'update_case_notes'.
    If so, it prunes previous large tool outputs that have already been 'synthesized'.
    """
    last_assistant = next((m for m in reversed(history) if m["role"] == "assistant"), None)
    if not last_assistant:
        return

    calls = last_assistant.get("tool_calls", [])
    has_notes = any(desanitize_tool_name(c["function"]["name"]) == "dfir.update_case_notes@1" for c in calls)
    
    if has_notes:
        # V15: Structured Claim Compaction
        # Find the tool result to ensure it was SUCCESS before compacting
        idx_last_assistant = 0
        for i, m in enumerate(history):
            if m is last_assistant:
                idx_last_assistant = i
                break
        
        for i in range(idx_last_assistant):
            m = history[i]
            if m["role"] == "tool" and len(m.get("content", "")) > 100000:
                m["content"] = "[COMPACTED: Content summarized in case notes. Use surgical query tools if you need to re-read specific fields.]"

def check_for_rca(history: list[dict]) -> tuple[bool, str]:
    """
    Checks if a machine-readable root_cause_analysis.json block exists and matches the schema.
    Returns (is_valid, error_message).
    """
    import jsonschema
    import re
    
    schema_path = Path(__file__).parent.parent.parent / "contracts" / "root_cause.schema.json"
    if not schema_path.exists():
        # Fallback if schema is missing during development
        return (False, "Root cause schema missing from 'contracts/root_cause.schema.json'.")
        
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
    except Exception as e:
        return (False, f"Failed to load RCA schema: {str(e)}")

def validate_case_notes(tool_args: dict) -> tuple[bool, str]:
    """
    V15: Validates structured case notes against claims schema.
    Returns (is_valid, error_msg).
    """
    import jsonschema
    schema_path = Path(__file__).parent.parent.parent / "contracts" / "case_notes.schema.json"
    if not schema_path.exists():
        return (True, "") # Fallback
    
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(instance=tool_args, schema=schema)
        
        # V35 Structural Enforcement (Verification Only)
        claims = tool_args.get("claims", [])
        for c in claims:
            stmt = c.get("statement", "").lower()
            ctype = c.get("type", "")
            if any(k in stmt for k in EPISTEMIC_SIGNALS["HYPOTHESIS"]) and ctype not in ["HYPOTHESIS", "ASSESSMENT", "GAP"]:
                    return (False, f"Epistemic Violation: Claim '{c['claim_id']}' uses inferential language ('{stmt}') but is marked as '{ctype}'. Must be HYPOTHESIS, ASSESSMENT, or GAP.")
            if ctype == "HYPOTHESIS" and not c.get("evidence_refs"):
                    return (False, f"Epistemic Violation: Hypothesis '{c['claim_id']}' must cite specific 'evidence_refs'.")
        return (True, "")
    except jsonschema.exceptions.ValidationError as ve:
        return (False, f"Case Notes Schema Validation Failed: {ve.message}")
    except Exception as e:
        return (False, f"Validation Error: {str(e)}")

def check_for_rca(history: list[dict]) -> tuple[bool, str]:
    """
    Checks if a machine-readable root_cause_analysis.json block exists and matches the schema.
    Returns (is_valid, error_message).
    """
    import jsonschema
    import re
    
    schema_path = Path(__file__).parent.parent.parent / "contracts" / "root_cause.schema.json"
    if not schema_path.exists():
        return (False, "Root cause schema missing from 'contracts/root_cause.schema.json'.")
        
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
    except Exception as e:
        return (False, f"Failed to load RCA schema: {str(e)}")

    for m in reversed(history):
        if m["role"] == "assistant" and "tool_calls" in m:
            for tc in m["tool_calls"]:
                if desanitize_tool_name(tc["function"]["name"]) == "dfir.update_case_notes@1":
                    try:
                        args = json.loads(tc["function"]["arguments"])
                        # V15 Update: Claims is now a list. We search all statement fields for the RCA block.
                        claims = args.get("claims", [])
                        for c in claims:
                            stmt = c.get("statement", "")
                            match = re.search(r"```json\s*(\{.*root_cause_analysis.*?\})\s*```", stmt, re.DOTALL | re.IGNORECASE)
                            if not match:
                                match = re.search(r"```json\s*(\{.*?\})\s*```", stmt, re.DOTALL)
                                
                            if match:
                                rca_data = json.loads(match.group(1))
                                jsonschema.validate(instance=rca_data, schema=schema)
                                return (True, "")
                    except jsonschema.exceptions.ValidationError as ve:
                        # V17: Provide specific feedback on missing fields
                        msg = ve.message
                        if "required" in msg.lower():
                            msg = f"RCA Schema Validation Failed: {msg}. Ensure 'summary', 'root_cause', 'confidence', 'claims', 'unknowns', and 'assessment' are ALL present."
                        return (False, msg)
                    except Exception:
                        continue
    return (False, "Root cause analysis block (JSON) not found in case notes.")


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


import time
import atexit

class PersistentMCPClient:
    def __init__(self, name: str, config: dict):
        self.name = name
        cmd = config["command"]
        cwd = config.get("cwd")
        self.process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        self.req_id = 1
        
        # Initialize handshake
        self._send({"jsonrpc": "2.0", "id": self.req_id, "method": "initialize", "params": {}})
        self._read_response(self.req_id)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        
    def _send(self, payload: dict):
        if self.process.poll() is not None:
            err = self.process.stderr.read()
            raise RuntimeError(f"MCP server '{self.name}' died unexpectedly.\nSTDERR: {err}")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        
    def _read_response(self, expected_id: int, timeout_s: int = 300) -> dict:
        start = time.time()
        while time.time() - start < timeout_s:
            if self.process.poll() is not None:
                err = self.process.stderr.read()
                raise RuntimeError(f"MCP server '{self.name}' died unexpectedly.\nSTDERR: {err}")
                
            line = self.process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                msg = json.loads(line)
                if msg.get("id") == expected_id:
                    return msg
            except json.JSONDecodeError:
                print(f"[!] MCP '{self.name}' stdout: {line[:100]}")
                
        raise TimeoutError(f"MCP server '{self.name}' response timeout for id {expected_id}")

    def call_tool(self, name: str, arguments: dict) -> dict:
        self.req_id += 1
        current_id = self.req_id
        self._send({"jsonrpc": "2.0", "id": current_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        resp = self._read_response(current_id)
        if "error" in resp:
            raise RuntimeError(f"MCP tools/call error: {json.dumps(resp['error'], indent=2)}")
        return resp["result"]
        
    def list_tools(self) -> list[dict]:
        self.req_id += 1
        current_id = self.req_id
        self._send({"jsonrpc": "2.0", "id": current_id, "method": "tools/list", "params": {}})
        resp = self._read_response(current_id)
        return resp.get("result", {}).get("tools", [])
        
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()

_ACTIVE_MCP_CLIENTS: Dict[str, PersistentMCPClient] = {}

def get_mcp_client(server_key: str) -> PersistentMCPClient:
    if server_key not in _ACTIVE_MCP_CLIENTS:
        if server_key not in MCP_SERVERS:
            raise ValueError(f"Unknown MCP server: {server_key}")
        _ACTIVE_MCP_CLIENTS[server_key] = PersistentMCPClient(server_key, MCP_SERVERS[server_key])
    return _ACTIVE_MCP_CLIENTS[server_key]

def _close_all_mcp_clients():
    for client in _ACTIVE_MCP_CLIENTS.values():
        try:
            client.close()
        except:
            pass
    _ACTIVE_MCP_CLIENTS.clear()

atexit.register(_close_all_mcp_clients)

def mcp_list_tools(server_key: str = "dfir") -> list[dict]:
    client = get_mcp_client(server_key)
    return client.list_tools()


def mcp_tools_call(name: str, arguments: dict, req_id: int = 3) -> dict:
    if name.startswith("dfir."):
        server_key = "dfir"
    elif name.startswith("memory_") or name.startswith("vt_"):
        server_key = "mem"
    else:
        server_key = "win"
        
    case_dir = os.environ.get("DFIR_CASE_DIR")
    if case_dir and server_key != "dfir":
        for k in ["output_dir", "dump_dir", "output_path"]:
            if k in arguments and isinstance(arguments[k], str):
                if not os.path.isabs(arguments[k]):
                    arguments[k] = os.path.join(case_dir, arguments[k])
            elif "dump" in name and k == "output_dir" and "output_dir" not in arguments:
                arguments["output_dir"] = case_dir

    client = get_mcp_client(server_key)
    return client.call_tool(name, arguments)


def mcp_read_json(path: str, json_pointer: Optional[str] = None, max_bytes: int = 100000) -> dict:
    args: Dict[str, Any] = {"path": path, "max_bytes": max_bytes}
    if json_pointer is not None:
        args["json_pointer"] = json_pointer

    raw = mcp_tools_call("dfir.read_json@1", args)
    if isinstance(raw, dict) and "value" in raw:
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("result"), dict) and "value" in raw["result"]:
        return raw["result"]
    return raw


def sanitize_tool_name(name: str) -> str:
    """DeepSeek/OpenAI requires ^[a-zA-Z0-9_-]+$. Mapping dfir.foo@1 -> dfir__foo__v1."""
    return name.replace(".", "__").replace("@", "__v")


def desanitize_tool_name(name: str) -> str:
    """Mapping dfir__foo__v1 -> dfir.foo@1 for MCP dispatch."""
    # V16 Fix: Use regex to only replace __v if it's followed by digits at the END
    # prevent collision with words like 'validate'
    name = re.sub(r'__v(\d+)$', r'@\1', name)
    # Replace __ with . (scoped to namespacing)
    if "__" in name:
        name = name.replace("__", ".")
    return name


def deepseek_chat(messages: list[dict], model: str, base_url: str, api_key: str, tools: Optional[list[dict]] = None, timeout_s: int = 60) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1024,
    }
    if tools:
        # Convert MCP tools to OpenAI function calling format with sanitized names
        openai_tools = []
        for t in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": sanitize_tool_name(t["name"]),
                    "description": t["description"],
                    "parameters": t["inputSchema"]
                }
            })
        body["tools"] = openai_tools
    # Check if we have tool calls in the last assistant message
    # DeepSeek API (like OpenAI) uses 'tool_choice' or 'tools' list
    # For now, we manually handle tool calls if they appear in content or as attributes
    
    encoded_body = json.dumps(body).encode("utf-8")
    req = Request(url, data=encoded_body, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
        raise RuntimeError(f"DeepSeek HTTPError {e.code}: {raw}")
    except URLError as e:
        raise RuntimeError(f"DeepSeek URLError: {e}")


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _get_skills_registry() -> str:
    """Scans .skills/ for SKILL.md files and parses YAML metadata."""
    registry = []
    skills_root = PROJECT_ROOT / ".skills"
    if not skills_root.is_dir():
        return ""

    for skill_dir in skills_root.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            continue

        try:
            content = skill_file.read_text(encoding="utf-8")
            # Quick YAML parser (regex) to avoid heavy dependencies
            # Extracts 'name: ...' and 'description: ...'
            name_match = re.search(r'^name:\s*(.+)$', content, re.MULTILINE)
            desc_match = re.search(r'^description:\s*(.+)$', content, re.MULTILINE)
            
            if name_match and desc_match:
                name = name_match.group(1).strip()
                desc = desc_match.group(1).strip()
                registry.append(f"- {name}: {desc}")
        except Exception as e:
            print(f"DEBUG: Failed to parse skill {skill_file.name}: {e}")

    if not registry:
        return ""

    header = "\nAVAILABLE SKILLS (Progressive Disclosure):\n"
    footer = "\nTo load the full instructions for a skill (or its supporting files), use dfir__load_skill__v1(skill_name='name', file_name=None).\n"
    return header + "\n".join(registry) + footer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--intake-json", required=True, help="Path to outputs/intake/<id>/intake.json")
    ap.add_argument("--mode", choices=["structured", "autonomous"], default="structured", help="Execution mode")
    ap.add_argument("--task", help="Optional specific task description to guide the investigation")
    args = ap.parse_args()

    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    
    intake_abs = os.path.abspath(args.intake_json)
    intake_dir = os.path.dirname(intake_abs)
    os.environ["DFIR_CASE_DIR"] = intake_dir

    if not api_key:
        print("FAIL: DEEPSEEK_API_KEY not set", file=sys.stderr)
        return 2

    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat").strip()
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip()

    ai_id = str(uuid.uuid4())
    ts = _now_utc_iso()

    # Read intake (bounded)
    intake = mcp_read_json(args.intake_json)["value"]
    intake_id = intake.get("intake_id", intake.get("case_id", "unknown"))
    os.environ["DFIR_CASE_ID"] = intake_id

    # Discovery Grounding (Case Envelope Implementation)
    dir_listing = []
    found_paths = {}
    case_summary_md = ""
    primary_finding_context = ""
    
    try:
        from tools.mcp.dfir_mcp_server import tool_list_dir, tool_read_text, tool_query_findings, symbolize_path
        res = tool_list_dir({"path": intake_dir}, {})
        if "entries" in res:
            # Fix: Handle both list of dicts or list of strings
            dir_listing = [e["name"] if isinstance(e, dict) else e for e in res["entries"]]
            
        # Prioritize major artifacts
        for e in res.get("entries", []):
            ename = e["name"] if isinstance(e, dict) else e
            epath = symbolize_path(os.path.join(intake_dir, ename))
            if ename == "case_summary.md":
                found_paths["Summary"] = epath
                summary_res = tool_read_text({"path": epath, "max_bytes": 100000}, {})
                if "value" in summary_res:
                    case_summary_md = summary_res["value"]
            elif ename == "case_findings.json":
                found_paths["Findings"] = epath
                # V7: Primary Finding Grounding (Turn 0)
                try:
                    pfind = tool_query_findings({"path": epath, "severity": "critical", "limit": 1}, {})
                    if pfind.get("results"):
                        primary_finding_context = json.dumps(pfind["results"][0], indent=2)
                except:
                    pass
            elif ename.endswith(".plaso"):
                found_paths["Timeline (Plaso)"] = epath
            elif ename == "auto.json":
                found_paths["Auto Enrichment"] = epath
            elif ename == "case_findings.json":
                found_paths["Case Findings"] = epath
            elif ename == "case_manifest.json":
                found_paths["Case Manifest"] = epath
            elif ename == "case_summary.md":
                found_paths["Case Summary"] = epath
            elif ename == "intake.json":
                found_paths["Intake Metadata"] = epath
            elif ename == "case.json":
                found_paths["Authoritative Case Metadata"] = epath
        
        # Also check for hoisted plaso at root (intake_dir)
        case_id = intake_id or intake.get("case_id")
        if case_id:
            hoisted_abs = os.path.join(intake_dir, f"{case_id}.plaso")
            if os.path.exists(hoisted_abs):
                found_paths["Timeline (Super)"] = symbolize_path(hoisted_abs)
        
        # V8: Executable Forensic Memory (CLAUDE.md)
        claude_md_path = os.path.join(intake_dir, "CLAUDE.md")
        claude_content = (
            "# Forensic Project Memory (SIFT Workstation)\n\n"
            "## Guardrails & Constraints\n"
            "- **100KB Limit**: Treat outputs > 100KB as data sources, not context. Use surgical query tools.\n"
            "- **Forensic Soundness**: Use read-only tools. Never modify original evidence paths.\n"
            "- **Convergence Contract**: You MUST produce `root_cause_analysis.json` before exiting.\n\n"
            "## Case Envelope (Absolute Paths)\n"
        )
        for label, path in found_paths.items():
            claude_content += f"- {label}: `{path}`\n"
        
        with open(claude_md_path, "w") as f:
            f.write(claude_content)
        found_paths["Project Memory"] = symbolize_path(claude_md_path)

    except Exception as e:
        print(f"DEBUG: Resource discovery failed: {e}")
        # Fallback path logic
        if not dir_listing and os.path.exists(intake_dir):
            dir_listing = os.listdir(intake_dir)

    out_dir = os.path.join(intake_dir, "orchestrator", ai_id)
    req_path = os.path.join(out_dir, "request.json")
    resp_path = os.path.join(out_dir, "response.json")
    err_path = os.path.join(out_dir, "error.json")
    summary_path = os.path.join(out_dir, "summary.md")

    try:
        # 1) Tool Discovery (New Production Invariant)
        mcp_tools = mcp_list_tools("dfir")
        
        # Phase 46: Discover memory forensics tools for memory dump cases
        is_memory_case = intake.get("classification", {}).get("kind") == "memory_dump_file"
        if is_memory_case:
            try:
                mem_tools = mcp_list_tools("mem")
                mcp_tools.extend(mem_tools)
                print(f"[+] Memory forensics: {len(mem_tools)} tools discovered from mem MCP server.")
            except Exception as e:
                print(f"[!] Warning: Could not discover mem MCP tools: {e}")
        
        # Rule 1: Early Guardrails & Redundancy Prevention
        if found_paths:
            mcp_tools = [t for t in mcp_tools if t["name"] != "dfir.load_intake@1"]
        
        # 2) Pre-calculate skills registry
        skills_registry = _get_skills_registry()

        mode_instructions = ""
        if args.mode == "autonomous":
            mode_instructions = (
                "You are an autonomous DFIR agent. You will not receive human feedback. "
                "You must execute this investigation end-to-end. If a tool command fails, "
                "read the error message, consult your loaded Skills, and retry with corrected syntax. "
                "When you have found the root cause, write your final findings to progress.md "
                "and output exactly <promise>TASK_COMPLETE</promise> to conclude the investigation."
            )
        else:
            mode_instructions = (
                "You are an interactive DFIR assistant. Before performing any deep analysis, "
                "you must formulate a plan and propose the tool you want to use. "
                "Wait for the lead investigator to approve your tool calls. "
                "If the investigator corrects you, adjust your command immediately."
            )

        system_prompt = (
            "You are a HIGH-VELOCITY DFIR triage assistant. You produce NON-AUTHORITATIVE commentary.\n"
            f"{mode_instructions}\n"
            f"{skills_registry}\n"
            "--- THE RALPH WIGGUM FORENSIC LOOP (V20) ---\n"
            "1. TASK: Execute the assigned DFIR investigation autonomously by chaining appropriate forensic tools, analyzing the outputs, and documenting all findings progressively in your case notes.\n"
            "2. PROCESS & SUCCESS CRITERIA: Make targeted, surgical queries. Use symbolic 'CASE://' URIs or 'case_ref': 'CASE' for all investigation artifacts to ensure portability.\n"
            "3. COMPLETION PROMISE: You must not stop or ask for human intervention until you have conclusively solved the task, noted any missing evidence gaps, and written your final structured conclusions to 'root_cause_analysis.json'.\n"
            "   * Once, and ONLY once, that file is fully written and validated, output exactly <promise>TASK_COMPLETE</promise> to terminate the loop.\n"
            "--- THE EPISTEMIC FORENSIC PROTOCOL (V35) ---\n"
            "1. STRUCTURED CLAIM OBJECTS: You MUST use 'dfir__update_case_notes__v1' with structured Claim Objects. Types:\n"
            "   - OBSERVATION: Direct finding from a tool (must cite evidence_refs). No causal language.\n"
            "   - DERIVED: Deterministic transform of observations (inputs + method). No inference.\n"
            "   - HYPOTHESIS: Causal/inferential interpretation (e.g., lateral movement, 'likely', 'suggests').\n"
            "   - ASSESSMENT: Weighted judgement after corroboration ('most probable root cause').\n"
            "   - GAP: Explicitly identified evidence/logging gaps (use 'impact' field).\n"
            "2. STRUCTURAL GUARDRAILS: Causal verbs ('caused', 'led to') or intent ('attacker', 'hide') REQUIRE labeling as HYPOTHESIS.\n"
            "3. STATUS TRANSITIONS: Claims start 'Open'. Transition to 'Supported' or 'Confirmed' only when corroboration is complete.\n"
            "3. DETERMINISTIC CORRELATION: You have access to 'dfir__correlate_pivot__v1'. Use this for common investigative moves (LogonId -> 4624/4634, PID -> 4688). Do NOT attempt to perform these mappings via raw reasoning.\n"
            "4. AUTOMATED PIVOT LADDER: If a surgical search (keyword) returns 0 results, you are REQUIRED to call 'dfir__pivot_ladder__v1' in the SAME turn to generate a metadata-based recovery plan. Do NOT waste budget on repeated failed keyword searches.\n"
            "5. TURN EFFICIENCY: 12-STEP DOOM CLOCK is active. 25 points budget (Timeline=3, Finding=2, Read=1). Turn efficiency is critical.\n"
            "   * BATCH FINDINGS: Use 'finding_ids' (array) in 'dfir__query_findings__v1' to retrieve multiple critical findings in a SINGLE turn. Querying findings one-by-one is considered a failure in efficiency.\n"
            "\nHard rules:\n"
            "- CRITICAL: Do NOT invent evidence or claim certainty without explicit fields from tool returns.\n"
            "- CRITICAL: Do NOT simulate tool outputs. You must wait for the actual tool call return.\n"
            "- FORENSIC SOUNDNESS: You are strictly forbidden from modifying evidence paths. Use read-only tools.\n"
            "- CONVERGENCE CONTRACT: You MUST produce a machine-readable 'root_cause_analysis.json' block in your case notes before you conclude. Reaching TASK_COMPLETE without it results in rejection.\n"
            "   * CRITICAL: Your RCA JSON MUST include the 'summary' field (Executive summary), 'root_cause', 'confidence', 'claims' (with supporting_evidence refs), 'unknowns', and 'assessment'.\n"
            "   * REJECTION WARNING: Omitting the 'summary' field will result in a hard validation error.\n"
            "- MANDATED TOOL CHAINING: ALWAYS batch 'update_case_notes' with your next investigative tool call.\n"
            "- PIVOT EXTRACTION: Every query result must produce extracted pivots.\n"
            "- When your investigation is fully concluded, YOU MUST output the exact token: <promise>TASK_COMPLETE</promise>\n"
            "- To use a tool, use the native tool calling capability OR output a JSON block like: ```json {\"dfir__tool_name__v1\": {\"arg\": \"val\"}} ```\n"
        )

        # Phase 46: Memory Forensics Protocol Injection
        if is_memory_case:
            evidence_paths = intake.get("inputs", {}).get("paths", [])
            evidence_file = evidence_paths[0] if evidence_paths else "unknown"
            # Resolve to absolute path
            abs_evidence = str((Path(os.environ.get("DFIR_CASE_DIR", ".")).parent.parent / evidence_file).resolve())
            if not os.path.exists(abs_evidence):
                # Try from project root
                abs_evidence = str((PROJECT_ROOT / evidence_file).resolve())

            system_prompt += (
                "\n--- MEMORY FORENSICS PROTOCOL (V46) ---\n"
                "This case contains a MEMORY DUMP file. Traditional EVTX/timeline tools will NOT work.\n"
                f"EVIDENCE FILE: {abs_evidence}\n"
                "MANDATORY WORKFLOW:\n"
                "1. FIRST: Call 'memory_full_triage' with image_path set to the evidence file path above.\n"
                "   This runs automated analysis (process listing, network scan, malware detection) and produces a comprehensive triage report.\n"
                "2. THEN: Use 'memory_run_plugin' for surgical follow-up (e.g., specific Vol3 plugins like windows.pslist.PsList, windows.netscan.NetScan, windows.cmdline.CmdLine).\n"
                "3. Use 'memory_hunt_process_anomalies' to find injected or hidden processes.\n"
                "4. Use 'memory_find_c2' to check for C2 beacons and suspicious network connections.\n"
                "5. Use 'memory_command_history' to extract command-line history from the dump.\n"
                "6. For string/flag searches, use 'memory_run_plugin' with plugin='search' and params={'pattern': 'PicoCTF'}.\n"
                "CRITICAL: The 'image_path' argument for ALL memory tools MUST be the absolute path shown above.\n"
                "CRITICAL: Do NOT waste turns trying dfir.list_dir or dfir.query_findings — there are no EVTX logs or pre-existing findings for memory dumps.\n"
            )

        user_task = args.task if args.task else "Begin investigation by running dfir.auto_run@1."
        
        # Intake Injection (Grounding)
        intake_context = json.dumps(intake, indent=2)
        
        # Grounding context construction
        context_payload = f"Intake ID: {intake_id}\nIntake Path: {args.intake_json}\nTask: {user_task}\n"
        
        if found_paths:
            context_payload += "\n[KNOWLEDGE] Primary Evidence References (Case Envelope):\n"
            for label, fpath in found_paths.items():
                context_payload += f"- {label}: {fpath}\n"

        context_payload += f"\n[CONTEXT] Auto-Detected Intake Payload:\n```json\n{intake_context}\n```\n"
        context_payload += f"\n[CONTEXT] Case Output Directory Listing ({symbolize_path(intake_dir)}):\n- " + "\n- ".join(dir_listing)
        
        if case_summary_md:
            context_payload += f"\n\n[CONTEXT] SITUATIONAL AWARENESS MAP (case_summary.md):\n```markdown\n{case_summary_md}\n```"

        if primary_finding_context:
            context_payload += f"\n\n[GROUNDING] Primary Critical Finding (Investigation Focus):\n```json\n{primary_finding_context}\n```"

        history = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_payload}
        ]
        
        # Verification Log: Write the initial request setup
        write_json(req_path, {
            "timestamp": ts,
            "system_prompt": system_prompt,
            "user_prompt": history[1]["content"],
            "mcp_tools_exposed": mcp_tools
        })

        MAX_ITERATIONS = 12
        iteration = 0
        budget_points = 25
        notes_count = 0
        has_fetched_evidence = False
        progress_jsonl = os.path.join(out_dir, "progress.jsonl")
        
        # Init progress.jsonl
        with open(progress_jsonl, "w") as f:
            f.write(json.dumps({"ts": ts, "event": "Investigation Started", "intake": intake_id}) + "\n")
            
        final_summary = "Investigation timed out or reached max iterations."

        while iteration < MAX_ITERATIONS:
            iteration += 1
            print(f"[*] Iteration {iteration}/{MAX_ITERATIONS}...")
            
            # Phase 18: Synthesis Pressure
            if iteration >= (MAX_ITERATIONS - 3):
                remaining = MAX_ITERATIONS - iteration + 1
                history.append({
                    "role": "system",
                    "content": f"[System WARNING]: You only have {remaining} iterations remaining. Stop exploring immediately. You MUST now synthesize your current pivots and OBSERVATIONS into a final 'root_cause_analysis.json'. Transition to synthesis and output the <promise>TASK_COMPLETE</promise> token."
                })
            
            # 5) Call DeepSeek with Discoverable Tools
            ds_response = deepseek_chat(history, model=model, base_url=base_url, api_key=api_key, tools=mcp_tools)
            choice = ds_response["choices"][0]
            message = choice["message"]
            content = message.get("content") or ""
            
            history.append(message)
            
            if content:
                print(f"[AI]: {content}")
                if "<promise>TASK_COMPLETE</promise>" in content:
                    # Convergence Contract Enforcement
                    is_valid, err_msg = check_for_rca(history)
                    if is_valid:
                        print("[*] Completion token detected and RCA validated.")
                        final_summary = content
                        break
                    else:
                        print(f"[!] WARNING: Completion attempted without Valid RCA. Error: {err_msg}")
                        history.append({
                            "role": "user",
                            "content": f"[System Error]: Cannot complete task. {err_msg} You MUST provide a schema-compliant 'root_cause_analysis.json' block (mapping claims to evidence IDs and listing unknowns) before concluding."
                        })
                        continue

            tool_calls = message.get("tool_calls") or []
            
            # Fallback 1: Parse normal markdown JSON blocks if native tool_calls is empty
            if not tool_calls and "```json" in content:
                try:
                    import re
                    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", content, re.DOTALL)
                    for block in blocks:
                        jb = json.loads(block)
                        for tname, targs in jb.items():
                            if tname.startswith("dfir."):
                                tool_calls.append({
                                    "id": f"call_{uuid.uuid4().hex[:8]}",
                                    "type": "function",
                                    "function": {"name": tname, "arguments": json.dumps(targs)}
                                })
                except Exception:
                    pass

            # Fallback 2: Parse DeepSeek native <｜DSML｜> tags
            if not tool_calls and "<｜DSML｜invoke" in content:
                try:
                    import re
                    # Look for <｜DSML｜invoke name="tool_name">...</｜DSML｜invoke>
                    invokes = re.findall(r"<｜DSML｜invoke name=\"(.*?)\">(.*?)</｜DSML｜invoke>", content, re.DOTALL)
                    for tname, inner_content in invokes:
                        args_dict = {}
                        # Extract parameters <｜DSML｜parameter name="arg_name">arg_value</｜DSML｜parameter>
                        params = re.findall(r"<｜DSML｜parameter name=\"(.*?)\".*?>(.*?)</｜DSML｜parameter>", inner_content, re.DOTALL)
                        for pname, pval in params:
                            args_dict[pname] = pval.strip()

                        # In case the model decided to just dump JSON as a string payload instead of discrete XML arguments
                        if not args_dict:
                            json_attempts = re.findall(r"(\{.*?\})", inner_content, re.DOTALL)
                            if json_attempts:
                                try:
                                    args_dict = json.loads(json_attempts[0])
                                except Exception:
                                    pass

                        tool_calls.append({
                            "id": f"call_{uuid.uuid4().hex[:8]}",
                            "type": "function",
                            "function": {"name": tname, "arguments": json.dumps(args_dict)}
                        })
                except Exception:
                    pass

            if tool_calls:
                message["tool_calls"] = tool_calls


            if not tool_calls:
                continue

            # V7: Parallel Tool Execution (Async Turns)
            # We collect all tool calls and run them in parallel if possible.
            # However, to preserve 'structured' mode logic (interception), we still process them.
            
            batch_tools = [desanitize_tool_name(tc["function"]["name"]) for tc in tool_calls]
            batch_has_evidence = any(t in ["dfir.query_super_timeline@1", "dfir.query_findings@1", "dfir.load_case_context@1"] for t in batch_tools)
            
            def execute_one(tc):
                nonlocal budget_points, notes_count, has_fetched_evidence
                
                c_id = tc.get("id", "none")
                func = tc["function"]
                s_name = func["name"]
                t_name = desanitize_tool_name(s_name)
                try:
                    t_args = json.loads(func["arguments"])
                except:
                    t_args = {}

                # Tool Cost Budgeting
                TOOL_COSTS = {
                    "dfir.query_super_timeline@1": 3,
                    "dfir.query_findings@1": 2,
                    "dfir.read_text@1": 1
                }
                cost = TOOL_COSTS.get(t_name, 0)
                if budget_points - cost < 0:
                    return {"id": c_id, "name": t_name, "error": f"[Budget Exceeded]: Tool '{t_name}' costs {cost} but you only have {budget_points} points left."}
                
                # First-Action Rule
                if iteration in [1, 2] and not has_fetched_evidence and not batch_has_evidence:
                    return {"id": c_id, "name": t_name, "error": "[First-Action Mandate]: You MUST execute a high-value evidence fetch (e.g., query_findings, query_super_timeline, or load_case_context) before further planning or note-taking."}

                # Note limit policy & V15 Epistemic Validation
                if t_name == "dfir.update_case_notes@1":
                    if notes_count >= 3:
                        return {"id": c_id, "name": t_name, "error": "[Policy Violation]: Maximum case note updates (3) reached. You must conclude the investigation."}
                    
                    # Phase 34: Auto-Epistemic Leveling
                    auto_correct_epistemic_claims(t_args)

                    # Epistemic integrity check
                    is_valid, err_msg = validate_case_notes(t_args)
                    if not is_valid:
                        return {"id": c_id, "name": t_name, "error": err_msg}
                        
                    notes_count += 1

                budget_points -= cost
                if t_name in ["dfir.query_super_timeline@1", "dfir.query_findings@1", "dfir.load_case_context@1"]:
                    has_fetched_evidence = True

                # Phase 11: Absolute Forensic Control - Redundancy Gate
                if t_name in ["dfir.load_intake@1"] and found_paths:
                    return {"id": c_id, "name": t_name, "error": "[Redundancy Guardrail]: Violation of efficiency protocol. The intake data and critical paths are ALREADY in your grounding context (Case Envelope). DO NOT rediscover. Proceed immediately with analysis."}

                # Validation
                v_err = validate_arguments(t_name, t_args, mcp_tools)
                if v_err:
                    return {"id": c_id, "name": t_name, "error": f"[Local Validation Error]: {v_err}"}

                # Interceptor (if structured)
                if args.mode == "structured" and t_name not in AUTO_APPROVE_TOOLS:
                    print(f"\n[AI PROPOSES TOOL]: {t_name}")
                    print(f"[ARGUMENTS]: {json.dumps(t_args, indent=2)}")
                    ch = input("Approve execution? [y/N/modify]: ").strip().lower()
                    if ch == 'modify':
                        fb = input("Provide your correction: ")
                        return {"id": c_id, "name": t_name, "error": f"[Human Intercept]: Denied. Suggestion: {fb}"}
                    elif ch != 'y':
                        return {"id": c_id, "name": t_name, "error": "[Human Intercept]: Execution denied by lead investigator."}

                # Execution
                try:
                    if t_name in AUTO_APPROVE_TOOLS:
                        print(f"[*] Safe-Pass: Auto-approving {t_name}")
                    
                    res = mcp_tools_call(t_name, t_args)
                    return {"id": c_id, "name": t_name, "result": res}
                except Exception as ex:
                    return {"id": c_id, "name": t_name, "error": f"[System Feedback]: Tool execution failed: {str(ex)}"}

            # Run parallelized with order preservation
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # executor.map preserves the order of the input iterable
                results = list(executor.map(execute_one, tool_calls))
                
                for r in results:
                    h_entry = {
                        "role": "tool",
                        "tool_call_id": r["id"],
                        "name": r["name"],
                    }
                    if "error" in r:
                        h_entry["content"] = r["error"]
                        print(f"  [-] {r['name']} failed: {r['error']}")
                        preview = r["error"]
                    else:
                        h_entry["content"] = json.dumps(r["result"])
                        preview = "SUCCESS"
                        print(f"  [+] {r['name']} success.")

                    history.append(h_entry)
                    
                    # JSONL Structured Progress Logging
                    try:
                        with open(progress_jsonl, "a") as f:
                            log_entry = {
                                "ts": _now_utc_iso(),
                                "step": f"Iteration {iteration}",
                                "tool": r["name"],
                                "result_preview": preview
                            }
                            f.write(json.dumps(log_entry) + "\n")
                    except Exception:
                        pass
            
            # V7: Active Compaction
            compact_history(history)

        # 6) Write summary.md (commentary artifact)
        md = [
            f"# DFIR Orchestrator Summary (NON-AUTHORITATIVE)\n",
            f"- intake_id: `{intake_id}`",
            f"- ai_id: `{ai_id}`",
            f"- iterations: `{iteration}`",
            "",
            final_summary.strip(),
            "",
            "## Audit Log",
        ]
        
        for h in history:
            role = h["role"].upper()
            content = h.get("content") or ""
            if role == "SYSTEM": continue
            
            md.append(f"### [{role}]")
            if h.get("tool_calls"):
                for tc in h["tool_calls"]:
                    md.append(f"- Proposes Tool: `{tc['function']['name']}`")
                    md.append(f"  - Args: `{tc['function']['arguments']}`")
            if role == "TOOL":
                md.append(f"- Tool Result Content:")
                md.append(f"```json\n{content}\n```")
            else:
                md.append(content)
            md.append("")

        write_text(summary_path, "\n".join(md))
        write_json(resp_path, history) # Full audit trail

        print(f"OK: wrote {summary_path}")
        return 0

    except Exception as e:
        write_json(err_path, {"error": str(e), "iteration": iteration})
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

