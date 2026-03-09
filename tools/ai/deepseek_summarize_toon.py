#!/usr/bin/env python3
"""
deepseek_summarize_toon.py

Goal:
- Take a TOON findings artifact (outputs/toon/.../findings.toon)
- Decode it to JSON (via @toon-format/cli)
- Build a defensible, bounded prompt using up to N findings
- Call an OpenAI-compatible chat endpoint (DeepSeek is OpenAI-compatible)
- ALWAYS write output artifacts:
    - decoded.json (the decoded TOON)
    - request.json (what we attempted to send)
    - summary.md (success OR failure report)
    - error.json (only on failure)

Why always write artifacts?
- DFIR pipeline must be auditable + reproducible even when AI calls fail (rate limits, outages, auth issues, etc.)
"""

import argparse
import json
import os
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from openai import OpenAI
except Exception as e:
    print("FAIL: missing 'openai' python package. Install with:", file=sys.stderr)
    print("  python3 -m pip install --user openai", file=sys.stderr)
    raise


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr


def decode_toon(toon_path: Path, decoded_path: Path) -> None:
    """
    Uses npx @toon-format/cli to decode TOON -> JSON.
    We do not implement a TOON parser here; we rely on the canonical CLI you already installed.
    """
    if not toon_path.is_file():
        raise FileNotFoundError(f"TOON input not found: {toon_path}")

    decoded_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "npx",
        "--yes",
        "@toon-format/cli",
        "--decode",
        "-o",
        str(decoded_path),
        str(toon_path),
    ]
    rc, out, err = run(cmd)
    if rc != 0:
        raise RuntimeError(
            "TOON decode failed.\n"
            f"cmd: {' '.join(cmd)}\n"
            f"rc: {rc}\n"
            f"stdout:\n{out}\n"
            f"stderr:\n{err}\n"
        )

    if not decoded_path.is_file() or decoded_path.stat().st_size == 0:
        raise RuntimeError(f"TOON decode produced no output: {decoded_path}")


def load_findings(decoded_json_path: Path, max_findings: int) -> Dict[str, Any]:
    doc = json.loads(decoded_json_path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(doc, dict):
        raise ValueError("Decoded JSON is not an object")

    findings = doc.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Decoded JSON has no 'findings' list")

    # Bounded selection: preserve determinism of ordering as stored.
    doc["findings"] = findings[:max_findings]
    return doc


def build_prompt(doc: Dict[str, Any]) -> str:
    """
    Prompt is intentionally bounded and structured.
    We do NOT ask the model to invent facts. We request:
    - top patterns
    - suspicious clusters
    - suggested next deterministic checks
    - triage priorities
    """
    run_md = doc.get("run_metadata", {})
    pipeline = (run_md.get("pipeline") or {}) if isinstance(run_md, dict) else {}
    src_tooling = (run_md.get("source_tooling") or {}) if isinstance(run_md, dict) else {}

    # Keep raw details limited but useful: we include essential fields per finding.
    findings_slim = []
    for f in doc.get("findings", []):
        if not isinstance(f, dict):
            continue
        findings_slim.append(
            {
                "finding_id": f.get("finding_id"),
                "category": f.get("category"),
                "summary": f.get("summary"),
                "confidence": f.get("confidence"),
                "severity": f.get("severity"),
                "source": f.get("source"),
                "evidence": {
                    "timestamps": (f.get("evidence") or {}).get("timestamps"),
                    "event_refs": (f.get("evidence") or {}).get("event_refs"),
                },
            }
        )

    payload = {
        "run_id": run_md.get("run_id"),
        "timestamp_utc": run_md.get("timestamp_utc"),
        "pipeline": pipeline,
        "source_tooling": src_tooling,
        "findings_count_in_prompt": len(findings_slim),
        "findings": findings_slim,
    }

    return (
        "You are a DFIR triage assistant. You must be conservative and evidence-driven.\n"
        "Rules:\n"
        "- Do NOT invent events, machines, users, or timelines.\n"
        "- If you speculate, label it clearly as a hypothesis.\n"
        "- Focus on patterns, clusters, and actionable next deterministic checks.\n"
        "- Output must be Markdown.\n"
        "\n"
        "Task:\n"
        "1) Executive summary (5-8 bullets): what stands out and why.\n"
        "2) Technical highlights: group findings into 3-6 clusters by theme (auth, services, registry, lateral movement, etc.).\n"
        "3) Top 10 findings to triage first: list finding_id, reason, what to validate next.\n"
        "4) Recommended next deterministic steps (commands/tools): e.g., which EVTX channels to pivot into, what to grep for, what to extract next.\n"
        "5) Confidence note: what evidence is missing that blocks stronger conclusions.\n"
        "\n"
        "Here is the bounded findings payload (JSON):\n"
        "```json\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
        + "\n```\n"
    )


def deepseek_chat(
    model: str,
    prompt: str,
    base_url: str,
    api_key: str,
    timeout_s: int = 120,
) -> str:
    """
    Calls an OpenAI-compatible chat endpoint.
    DeepSeek typically supports the OpenAI Chat Completions style via base_url+api_key.
    """
    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout_s,
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a careful DFIR assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )

    # openai>=2.x response shape
    text = (resp.choices[0].message.content or "").strip()
    return text


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--toon", required=True, help="Path to findings.toon")
    ap.add_argument("--out", required=True, help="Output markdown path (summary.md)")
    ap.add_argument("--model", default="deepseek-chat", help="Model name (default: deepseek-chat)")
    ap.add_argument("--max-findings", type=int, default=30, help="Max findings to include in prompt (default: 30)")
    ap.add_argument("--base-url", default=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                    help="OpenAI-compatible base URL (env: DEEPSEEK_BASE_URL). Default: https://api.deepseek.com")
    ap.add_argument("--api-key-env", default="DEEPSEEK_API_KEY",
                    help="Which env var contains the API key (default: DEEPSEEK_API_KEY)")
    ap.add_argument("--timeout", type=int, default=120, help="HTTP timeout seconds (default: 120)")
    args = ap.parse_args()

    toon_path = Path(args.toon).expanduser().resolve()
    out_md = Path(args.out).expanduser().resolve()

    # Put artifacts next to out_md (same directory) for easy auditing.
    out_dir = out_md.parent
    decoded_json = out_dir / "decoded.json"
    request_json = out_dir / "request.json"
    error_json = out_dir / "error.json"

    api_key = os.environ.get(args.api_key_env, "").strip()

    # Always create a summary.md even if we fail early (DFIR pipeline rule).
    try:
        if not api_key:
            raise RuntimeError(
                f"Missing API key. Set env var {args.api_key_env}.\n"
                f"Example:\n"
                f"  export {args.api_key_env}='YOUR_KEY'\n"
            )

        decode_toon(toon_path, decoded_json)
        doc = load_findings(decoded_json, args.max_findings)
        prompt = build_prompt(doc)

        request_obj = {
            "generated_utc": utc_now_iso(),
            "provider": "openai-compatible",
            "base_url": args.base_url,
            "model": args.model,
            "max_findings": args.max_findings,
            "toon_path": str(toon_path),
            "decoded_json": str(decoded_json),
        }
        write_json(request_json, request_obj)

        md = deepseek_chat(
            model=args.model,
            prompt=prompt,
            base_url=args.base_url,
            api_key=api_key,
            timeout_s=args.timeout,
        )

        if not md:
            raise RuntimeError("LLM returned empty response")

        header = (
            f"# DFIR AI Triage Summary\n\n"
            f"- Generated (UTC): {utc_now_iso()}\n"
            f"- Model: `{args.model}`\n"
            f"- Base URL: `{args.base_url}`\n"
            f"- Input TOON: `{toon_path}`\n"
            f"- Decoded JSON: `{decoded_json}`\n\n"
            f"---\n\n"
        )

        write_md(out_md, header + md + "\n")
        return 0

    except Exception as e:
        # Write failure artifacts so your pipeline is still auditable.
        tb = traceback.format_exc()
        err_obj = {
            "generated_utc": utc_now_iso(),
            "error": str(e),
            "traceback": tb,
            "toon_path": str(toon_path),
            "out_md": str(out_md),
            "decoded_json": str(decoded_json),
            "request_json": str(request_json),
        }
        try:
            write_json(error_json, err_obj)
        except Exception:
            pass

        fail_md = (
            f"# DFIR AI Triage Summary (FAILED)\n\n"
            f"- Generated (UTC): {utc_now_iso()}\n"
            f"- Model: `{args.model}`\n"
            f"- Base URL: `{args.base_url}`\n"
            f"- Input TOON: `{toon_path}`\n\n"
            f"## What happened\n"
            f"AI summarization failed, but deterministic artifacts remain available.\n\n"
            f"### Error\n"
            f"```\n{str(e)}\n```\n\n"
            f"### Traceback (first ~80 lines)\n"
            f"```text\n" + "\n".join(tb.splitlines()[:80]) + "\n```\n\n"
            f"## Next actions\n"
            f"- Check API key env `{args.api_key_env}` is set and has funds/permissions.\n"
            f"- Re-run the command; if it’s a transient error, it should succeed.\n"
            f"- Review `{error_json}` for the full traceback.\n"
        )
        try:
            write_md(out_md, fail_md)
        except Exception:
            pass

        return 2


if __name__ == "__main__":
    raise SystemExit(main())

