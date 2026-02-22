#!/usr/bin/env python3
import argparse
import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_CATEGORIES = {
    "execution",
    "persistence",
    "credential_access",
    "lateral_movement",
    "defense_evasion",
    "collection",
    "exfiltration",
    "impact",
    "discovery",
    "unknown",
}

def normalize_category(raw: str) -> str:
    if not raw:
        return "unknown"
    raw = str(raw).strip().lower()
    return raw if raw in ALLOWED_CATEGORIES else "unknown"

ALLOWED_SEVERITIES = {"informational", "low", "medium", "high", "critical"}

def normalize_severity(raw):
    if raw is None:
        return None
    v = str(raw).strip().lower()
    if v == "info":
        v = "informational"
    return v if v in ALLOWED_SEVERITIES else None

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--timestamp-utc", required=True)
    ap.add_argument("--pipeline-name", required=True)
    ap.add_argument("--pipeline-version", required=True)
    ap.add_argument("--chainsaw-version", required=True)
    ap.add_argument("--input-jsonl", required=True)
    ap.add_argument("--output-json", required=True)
    args = ap.parse_args()

    in_path = args.input_jsonl
    out_path = args.output_json

    if not os.path.isfile(in_path):
        raise SystemExit(f"FAIL: input_jsonl not found: {in_path}")

    # Minimal, defensible metadata: only what we can assert deterministically
    # Environment metadata is computed from the runtime (no hardcoded values)
    import platform
    import subprocess

    def read_os_pretty() -> str:
        try:
            data = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").splitlines()
            kv = {}
            for line in data:
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k] = v.strip().strip('"')
            return kv.get("PRETTY_NAME") or kv.get("NAME") or "unknown"
        except Exception:
            return "unknown"

    def read_timezone() -> str:
        # Prefer /etc/timezone when present; else try timedatectl; else unknown
        try:
            tz = Path("/etc/timezone").read_text(encoding="utf-8", errors="ignore").strip()
            if tz:
                return tz
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["timedatectl", "show", "-p", "Timezone", "--value"],
                text=True
            ).strip()
            if out:
                return out
        except Exception:
            pass
        return "unknown"

    environment = {
        "hostname": platform.node() or "unknown",
        "os": read_os_pretty(),
        "timezone": read_timezone(),
    }

    run_metadata = {
        "run_id": args.run_id,
        "timestamp_utc": args.timestamp_utc,
        "environment": environment,
        "generated_utc": now_utc_iso(),
        "pipeline": {
            "name": args.pipeline_name,
            "version": args.pipeline_version,
        },
        "source_tooling": {
            "chainsaw": {
                "version": args.chainsaw_version,
            }
        },
        "inputs": {
            "chainsaw_jsonl": {
                "path": os.path.abspath(in_path),
                "sha256": sha256_file(in_path),
                "size_bytes": os.path.getsize(in_path),
            }
        }
    }

    findings = []
    requests = []

    # Parse chainsaw jsonl. We will not assume a fixed schema beyond "a JSON object per line".
    # We treat each line as a "hit" record and preserve it as raw_ref.
    with open(in_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Deterministic behavior: record a request to re-run / inspect because input is malformed.
                requests.append({
                    "request_id": f"REQ-JSONL-PARSE-{idx}",
                    "type": "data_quality",
                    "summary": "Chainsaw output contained a non-JSON line",
                    "details": {
                        "line_number": idx,
                        "input": os.path.abspath(in_path),
                    }
                })
                continue

            # Build a stable finding_id from run_id + line_number (deterministic, no global counters)
            fid = f"F-{args.run_id[:8]}-{idx:06d}"

            # Deterministic labels derived only from Chainsaw record fields
            category_raw = rec.get("group") or rec.get("kind") or rec.get("type")
            rule_title = rec.get("name") or rec.get("title") or "Chainsaw hit"

            finding = {
                "finding_id": fid,
                "category": normalize_category(category_raw),

                "summary": rec.get("name") or rec.get("title") or rec.get("rule") or "Chainsaw hit",
                "confidence": rec.get("confidence") if rec.get("confidence") is not None else None,
                "severity": normalize_severity(rec.get("level") or rec.get("severity")),

                "source": {
                    "tool": "chainsaw",
                    "rule_id": (
                        rec.get("id")
                        or rec.get("rule_id")
                        or rec.get("rule")
                        or f"RAWREF:{os.path.basename(in_path)}:line:{idx}"
                    ),
                    "rule_title": str(rule_title),
                },

                "evidence": {
                    "event_refs": [f"{os.path.basename(in_path)}:line:{idx}"],
                    "artifacts": [],
                    "timestamps": {
                        "first_seen": rec.get("timestamp") or rec.get("time") or args.timestamp_utc,
                        "last_seen": rec.get("timestamp") or rec.get("time") or args.timestamp_utc
                    },
                    "raw": rec
                },
                "raw_refs": [f"{os.path.basename(in_path)}:line:{idx}"]
            }
            findings.append(finding)

    doc = {
        "run_metadata": run_metadata,
        "findings": findings,
        "requests": requests
    }

    with open(out_path, "w", encoding="utf-8") as out:
        json.dump(doc, out, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    raise SystemExit(main())

