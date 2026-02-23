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

MCP_SERVERS = {
    "dfir": {
        "command": ["python3", "-u", str(PROJECT_ROOT / "tools/mcp/dfir_mcp_server.py")],
        "cwd": PROJECT_ROOT
    },
    "win": {
        "command": [
            str(PROJECT_ROOT / "tools/mcp/mcp-windows/venv/bin/python3"),
            "-u",
            "-m",
            "winforensics_mcp.server"
        ],
        "cwd": PROJECT_ROOT / "tools/mcp/mcp-windows/winforensics-mcp"
    },
    "mem": {
        "command": [
            str(PROJECT_ROOT / "tools/mcp/memory/mem_forensics-mcp/venv/bin/python3"),
            "-u",
            "-m",
            "mem_forensics_mcp.server"
        ],
        "cwd": PROJECT_ROOT / "tools/mcp/memory/mem_forensics-mcp"
    }
}

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
        # Synchronized 100KB Compaction
        idx_last_assistant = 0
        for i, m in enumerate(history):
            if m is last_assistant:
                idx_last_assistant = i
                break
        
        for i in range(idx_last_assistant):
            m = history[i]
            if m["role"] == "tool" and len(m.get("content", "")) > 100000:
                m["content"] = "[COMPACTED: Content summarized in case notes. Use surgical query tools if you need to re-read specific fields.]"

def check_for_rca(history: list[dict]) -> bool:
    """
    Checks if a machine-readable root_cause_analysis.json block exists in any update_case_notes calls.
    """
    for m in reversed(history):
        if m["role"] == "assistant" and "tool_calls" in m:
            for tc in m["tool_calls"]:
                if desanitize_tool_name(tc["function"]["name"]) == "dfir.update_case_notes@1":
                    try:
                        args = json.loads(tc["function"]["arguments"])
                        notes = args.get("notes", "")
                        if "root_cause_analysis.json" in notes.lower() or "root_cause_analysis" in notes.lower():
                            return True
                    except Exception:
                        continue
    return False


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_mcp_lines(lines: list[str], server_key: str) -> list[dict]:
    """
    Runs the specified MCP server once with the provided JSON-RPC lines over stdin.
    Returns parsed JSON objects from stdout lines.
    """
    config = MCP_SERVERS[server_key]
    cmd = config["command"]
    cwd = config.get("cwd")

    payload = "\n".join(lines) + "\n"
    p = subprocess.run(
        cmd,
        cwd=cwd,
        input=payload.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    out = p.stdout.decode("utf-8", errors="replace").strip().splitlines()
    objs = []
    for line in out:
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            err = p.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"MCP emitted non-JSON line: {line[:200]}\nSTDERR: {err}")
    
    if not objs:
        err = p.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"MCP server '{server_key}' returned no response.\nSTDERR: {err}")
            
    return objs


def mcp_list_tools(server_key: str = "dfir") -> list[dict]:
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]
    objs = _run_mcp_lines(lines, server_key)
    for o in objs:
        if o.get("id") == 2:
            return o["result"].get("tools", [])
    return []


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

    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}),
    ]
    objs = _run_mcp_lines(lines, server_key)
    # Find response matching req_id
    for o in objs:
        if o.get("id") == req_id:
            if "error" in o:
                raise RuntimeError(f"MCP tools/call error: {json.dumps(o['error'], indent=2)}")
            return o["result"]
    raise RuntimeError("MCP tools/call: missing response")


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
    if "__v" in name:
        name = name.replace("__v", "@")
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
    intake_id = intake.get("intake_id", "unknown")
    os.environ["DFIR_CASE_ID"] = intake_id

    # Discovery Grounding (Case Envelope Implementation)
    dir_listing = []
    found_paths = {}
    case_summary_md = ""
    primary_finding_context = ""
    
    try:
        from tools.mcp.dfir_mcp_server import tool_list_dir, tool_read_text, tool_query_findings
        res = tool_list_dir({"path": intake_dir}, {})
        if "entries" in res:
            # Fix: Handle both list of dicts or list of strings
            dir_listing = [e["name"] if isinstance(e, dict) else e for e in res["entries"]]
            
        # Prioritize major artifacts
        for e in res.get("entries", []):
            ename = e["name"] if isinstance(e, dict) else e
            epath = os.path.join(intake_dir, ename)
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
        found_paths["Project Memory"] = claude_md_path

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
            "You are a DFIR triage assistant. You produce NON-AUTHORITATIVE commentary.\n"
            f"{mode_instructions}\n"
            f"{skills_registry}\n"
            "Hard rules:\n"
            "- CRITICAL: Do NOT invent evidence or claim certainty without explicit fields from tool returns.\n"
            "- CRITICAL: Do NOT simulate tool outputs. You must wait for the actual tool call return.\n"
            "- Use ONLY the JSON provided or results from tool calls.\n"
            "- When you successfully extract an artifact, YOU MUST use 'dfir__update_case_notes__v1' to document it.\n"
            "- Every note you write via 'dfir__update_case_notes__v1' MUST conclude with a 'Next Steps' summary.\n"
            "- When your investigation is fully concluded, YOU MUST output the exact token: <promise>TASK_COMPLETE</promise>\n"
            "- Output FORMAT: (1) Executive summary, (2) suspicious clusters, (3) Next deterministic pivots.\n"
            "- To use a tool, use the native tool calling capability OR output a JSON block like: ```json {\"dfir__tool_name__v1\": {\"arg\": \"val\"}} ```\n\n"
            "--- FORENSIC PROJECT MEMORY & GUARDRAILS (V8) ---\n"
            "- TREAT LARGE TOOL OUTPUTS AS DATA SOURCES, NOT CONTEXT. If a file exceeds 100KB, reading it directly WILL FAIL. You MUST use 'dfir__query_findings__v1' for surgical extraction.\n"
            "- FORENSIC SOUNDNESS: You are strictly forbidden from modifying evidence paths. Use read-only tools.\n"
            "- CONVERGENCE CONTRACT: You MUST produce a machine-readable 'root_cause_analysis.json' block in your case notes before you conclude. Reaching TASK_COMPLETE without an RCA will result in rejection.\n"
            "- CASE ENVELOPE: I have provided absolute paths to critical resources below. Use these directly. [BILLING/EFFICIENCY ALERT]: DO NOT use 'load_intake' or 'list_dir' to rediscover these paths. Re-discovery turns are a violation of efficiency protocol and will be blocked.\n"
            "- PLASO ABSTRACTION: Use 'dfir__query_super_timeline__v1' with structured JSON. Do NOT attempt to write raw Plaso filter strings.\n"
        )

        user_task = args.task if args.task else "Begin investigation by running dfir.auto_run@1."
        
        # Intake Injection (Grounding)
        intake_context = json.dumps(intake, indent=2)
        
        # Grounding context construction
        context_payload = f"Intake ID: {intake_id}\nIntake Path: {args.intake_json}\nTask: {user_task}\n"
        
        if found_paths:
            context_payload += "\n[KNOWLEDGE] Primary Evidence Paths (Case Envelope):\n"
            for label, fpath in found_paths.items():
                context_payload += f"- {label}: {fpath}\n"

        context_payload += f"\n[CONTEXT] Auto-Detected Intake Payload:\n```json\n{intake_context}\n```\n"
        context_payload += f"\n[CONTEXT] Case Output Directory Listing ({intake_dir}):\n- " + "\n- ".join(dir_listing)
        
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

        MAX_ITERATIONS = 10
        iteration = 0
        final_summary = "Investigation timed out or reached max iterations."

        while iteration < MAX_ITERATIONS:
            iteration += 1
            print(f"[*] Iteration {iteration}/{MAX_ITERATIONS}...")
            
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
                    if check_for_rca(history):
                        print("[*] Completion token detected and RCA validated.")
                        final_summary = content
                        break
                    else:
                        print("[!] WARNING: Completion attempted without Root Cause Analysis. Injecting enforcement.")
                        history.append({
                            "role": "user",
                            "content": "[SYSTEM ERROR]: Task rejected. You have not provided a structured 'root_cause_analysis.json' in your case notes yet. You MUST summarize your findings in a final RCA block before exiting."
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
            
            def execute_one(tc):
                c_id = tc.get("id", "none")
                func = tc["function"]
                s_name = func["name"]
                t_name = desanitize_tool_name(s_name)
                try:
                    t_args = json.loads(func["arguments"])
                except:
                    t_args = {}

                # Phase 11: Absolute Forensic Control - Redundancy Gate
                if t_name in ["dfir.load_intake@1", "dfir.list_dir@1"] and found_paths:
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
                    else:
                        h_entry["content"] = json.dumps(r["result"])
                        print(f"  [+] {r['name']} success.")
                    
                    history.append(h_entry)
            
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

