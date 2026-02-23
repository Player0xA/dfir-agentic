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
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()

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


def _now_utc_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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


def mcp_read_json(path: str, json_pointer: Optional[str] = None, max_bytes: int = 1048576) -> dict:
    args: Dict[str, Any] = {"path": path, "max_bytes": max_bytes}
    if json_pointer is not None:
        args["json_pointer"] = json_pointer

    raw = mcp_tools_call("dfir.read_json@1", args)
    if isinstance(raw, dict) and "value" in raw:
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("result"), dict) and "value" in raw["result"]:
        return raw["result"]
    return raw


def deepseek_chat(messages: list[dict], model: str, base_url: str, api_key: str, tools: Optional[list[dict]] = None, timeout_s: int = 60) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1024,
    }
    if tools:
        # Convert MCP tools to OpenAI function calling format
        openai_tools = []
        for t in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
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
    footer = "\nTo load the full instructions for a skill (or its supporting files), use dfir.load_skill@1(skill_name='name', file_name=None).\n"
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
            "- When you successfully extract an artifact, YOU MUST use 'dfir.update_case_notes@1' to document it.\n"
            "- Every note you write via 'dfir.update_case_notes@1' MUST conclude with a 'Next Steps' summary.\n"
            "- When your investigation is fully concluded, YOU MUST output the exact token: <promise>TASK_COMPLETE</promise>\n"
            "- Output FORMAT: (1) Executive summary, (2) suspicious clusters, (3) Next deterministic pivots.\n"
            "- To use a tool, use the native tool calling capability OR output a JSON block like: ```json {\"tool_name\": {\"arg\": \"val\"}} ```\n"
        )

        user_task = args.task if args.task else "Begin investigation by running dfir.auto_run@1."
        
        # Intake Injection (Grounding)
        intake_context = json.dumps(intake, indent=2)
        
        history = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Intake ID: {intake_id}\nIntake Path: {args.intake_json}\nTask: {user_task}\n\n[CONTEXT] Auto-Detected Intake Payload:\n```json\n{intake_context}\n```"}
        ]

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
                    print("[*] Completion token detected.")
                    final_summary = content
                    break

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

            for tool_call in tool_calls:
                call_id = tool_call.get("id", "none")
                function = tool_call["function"]
                name = function["name"]
                try:
                    arguments = json.loads(function["arguments"])
                except Exception as e:
                    arguments = {}
                    print(f"  [-] Failed to parse arguments for {name}: {e}")

                print(f"[*] Executing Tool: {name}...")
                
                # Structured Mode Interceptor
                if args.mode == "structured":
                    print(f"\n[AI PROPOSES TOOL]: {name}")
                    print(f"[ARGUMENTS]: {json.dumps(arguments, indent=2)}")
                    choice = input("Approve execution? [y/N/modify]: ").strip().lower()
                    
                    if choice == 'y':
                        pass # Proceed to execution
                    elif choice == 'modify':
                        feedback = input("Provide your correction: ")
                        error_msg = f"[Human Intercept]: Denied. Suggestion: {feedback}"
                        history.append({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": name,
                            "content": error_msg
                        })
                        continue
                    else:
                        print("  [-] Execution denied by human.")
                        history.append({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": name,
                            "content": "[Human Intercept]: Execution denied by lead investigator."
                        })
                        continue

                try:
                    result = mcp_tools_call(name, arguments)
                    history.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": json.dumps(result)
                    })
                    print(f"  [+] Success.")
                except Exception as e:
                    error_msg = f"[System Feedback]: Tool execution failed with error: {str(e)}. Review your loaded Skills, correct the syntax, and try again."
                    print(f"  [-] Failure: {str(e)}")
                    history.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": error_msg
                    })

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

