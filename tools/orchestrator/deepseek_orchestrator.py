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
import subprocess
import sys
import uuid
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


MCP_SERVERS = {
    "dfir": {
        "command": ["python3", "-u", "tools/mcp/dfir_mcp_server.py"],
    },
    "win": {
        "command": [
            "tools/mcp/memory/winforensics-mcp/venv/bin/python3",
            "-u",
            "tools/mcp/memory/winforensics-mcp/winforensics_mcp/server.py"
        ],
        "cwd": "tools/mcp/memory/winforensics-mcp"
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
    # stderr is intentionally not treated as failure: tools may log to stderr.
    objs = []
    for line in out:
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            # If MCP ever prints non-JSON, treat as hard failure.
            raise RuntimeError(f"MCP emitted non-JSON line: {line[:200]}")
    return objs


def mcp_tools_call(name: str, arguments: dict, req_id: int = 2) -> dict:
    server_key = "dfir" if name.startswith("dfir.") else "win"
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
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

    # Robust unwrap:
    # - Expected: {"call_id": "...", "result": {"path":..., "json_pointer":..., "value": ...}}
    # - Also accept already-unwrapped: {"path":..., "json_pointer":..., "value": ...}
    if isinstance(raw, dict) and "value" in raw:
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("result"), dict) and "value" in raw["result"]:
        return raw["result"]

    raise RuntimeError(f"Unexpected dfir.read_json@1 shape. Keys={list(raw.keys()) if isinstance(raw, dict) else type(raw)}")


def deepseek_chat(messages: list[dict], model: str, base_url: str, api_key: str, timeout_s: int = 60) -> dict:
    """
    Calls DeepSeek chat completions.
    Docs: POST https://api.deepseek.com/chat/completions (OpenAI-compatible shape).
    """
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 900,
        }
    ).encode("utf-8")

    req = Request(url, data=body, method="POST")
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--intake-json", required=True, help="Path to outputs/intake/<id>/intake.json")
    args = ap.parse_args()

    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
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

    out_dir = os.path.join("outputs", "ai", "orchestrator", intake_id, ai_id)
    req_path = os.path.join(out_dir, "request.json")
    resp_path = os.path.join(out_dir, "response.json")
    err_path = os.path.join(out_dir, "error.json")
    summary_path = os.path.join(out_dir, "summary.md")

    try:
        # 1) Execute deterministic auto run via MCP (this is your autonomous stack)
        auto_res = mcp_tools_call("dfir.auto_run@1", {"intake_json": args.intake_json})
        auto_json_path = auto_res["result"]["auto_json"]

        # 2) Read dispatch block (tiny pointer read)
        dispatch = mcp_read_json(auto_json_path, "/dispatch")["value"]
        run_id = dispatch.get("run_id")
        manifest_path = dispatch.get("manifest_path")

        # 3) Read manifest pointers to artifacts we are allowed to summarize
        # Only grab triage + a few metadata fields; do NOT read raw logs.
        manifest_tooling = mcp_read_json(manifest_path, "/tooling")["value"]
        triage_meta = mcp_read_json(manifest_path, "/artifacts/triage_json")["value"]
        findings_meta = mcp_read_json(manifest_path, "/artifacts/findings_json")["value"]

        triage_path = triage_meta["path"]
        findings_path = findings_meta["path"]

        triage = mcp_read_json(triage_path)["value"]

        # Optional: pull only the first N findings summaries (bounded) via JSON pointer if your findings are big.
        # Here we keep it simple: don't load findings.json at all unless you want it.
        # If you later want it, prefer pointers like "/findings/0" etc.
        # findings = mcp_read_json(findings_path)["value"]

        # 4) Build a strict “commentary-only” prompt
        system = {
            "role": "system",
            "content": (
                "You are a DFIR triage assistant. You produce NON-AUTHORITATIVE commentary.\n"
                "Hard rules:\n"
                "- Do NOT invent evidence or claim certainty without explicit fields.\n"
                "- Use only the JSON provided.\n"
                "- Output: (1) Executive triage summary, (2) Top suspicious clusters, (3) Next deterministic pivots.\n"
                "- Always reference finding_id when discussing an item.\n"
                "- If data is missing, say 'unknown'."
            ),
        }

        user = {
            "role": "user",
            "content": json.dumps(
                {
                    "timestamp_utc": ts,
                    "intake": {
                        "intake_id": intake_id,
                        "classification": intake.get("classification", {}),
                        "signals": intake.get("signals", []),
                        "inputs": intake.get("inputs", {}),
                    },
                    "deterministic_run": {
                        "run_id": run_id,
                        "manifest_path": manifest_path,
                        "tooling": manifest_tooling,
                        "triage_path": triage_path,
                        "findings_path": findings_path,
                    },
                    "triage": triage,
                },
                indent=2,
            ),
        }

        ds_request = {
            "provider": "deepseek",
            "base_url": base_url,
            "model": model,
            "messages": [system, user],
        }
        write_json(req_path, ds_request)

        # 5) Call DeepSeek
        ds_response = deepseek_chat([system, user], model=model, base_url=base_url, api_key=api_key)
        write_json(resp_path, ds_response)

        content = ""
        try:
            content = ds_response["choices"][0]["message"]["content"]
        except Exception:
            content = json.dumps(ds_response, indent=2)

        # 6) Write summary.md (commentary artifact)
        md = []
        md.append(f"# DFIR Orchestrator Summary (NON-AUTHORITATIVE)\n")
        md.append(f"- intake_id: `{intake_id}`")
        md.append(f"- ai_id: `{ai_id}`")
        md.append(f"- run_id: `{run_id}`")
        md.append(f"- manifest: `{manifest_path}`")
        md.append("")
        md.append(content.strip())
        md.append("")
        write_text(summary_path, "\n".join(md))

        print(f"OK: wrote {summary_path}")
        return 0

    except Exception as e:
        write_json(
            err_path,
            {
                "timestamp_utc": ts,
                "intake_json": args.intake_json,
                "ai_id": ai_id,
                "error": str(e),
            },
        )
        print(f"FAIL: {e}", file=sys.stderr)
        print(f"Wrote: {err_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

