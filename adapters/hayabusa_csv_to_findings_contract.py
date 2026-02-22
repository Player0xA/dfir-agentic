#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ALLOWED_SEVERITIES = {"informational", "low", "medium", "high", "critical"}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

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
    try:
        tz = Path("/etc/timezone").read_text(encoding="utf-8", errors="ignore").strip()
        if tz:
            return tz
    except Exception:
        pass
    try:
        out = subprocess.check_output(["timedatectl", "show", "-p", "Timezone", "--value"], text=True).strip()
        if out:
            return out
    except Exception:
        pass
    return "unknown"

def get_col(row: Dict[str, str], key: str) -> str:
    return (row.get(key) or "").strip()

def normalize_severity(raw: str) -> Optional[str]:
    v = (raw or "").strip().lower()
    if not v:
        return None
    if v == "info":
        v = "informational"
    return v if v in ALLOWED_SEVERITIES else None

def category_from_mitre_tactics(row: Dict[str, str]) -> str:
    # Deterministic mapping; conservative fallback to unknown.
    tactics = get_col(row, "MitreTactics").lower()

    if "execution" in tactics:
        return "execution"
    if "persistence" in tactics:
        return "persistence"
    if "credential access" in tactics or "credential_access" in tactics:
        return "credential_access"
    if "lateral movement" in tactics or "lateral_movement" in tactics:
        return "lateral_movement"
    if "defense evasion" in tactics or "defense_evasion" in tactics:
        return "defense_evasion"
    if "collection" in tactics:
        return "collection"
    if "exfiltration" in tactics:
        return "exfiltration"
    if "impact" in tactics:
        return "impact"
    if "discovery" in tactics:
        return "discovery"
    return "unknown"

def mk_finding_id(run_id: str, n: int) -> str:
    # must match ^F-[A-Za-z0-9._:-]{4,64}$
    return f"F-{run_id}-{n:06d}"

def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Hayabusa timeline CSV into dfir-agentic findings contract")
    ap.add_argument("--input-csv", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--timestamp-utc", required=True)
    ap.add_argument("--pipeline-name", required=True)
    ap.add_argument("--pipeline-version", required=True)
    ap.add_argument("--hayabusa-version", required=True)
    ap.add_argument("--evtx-dir", required=True)
    ap.add_argument("--profile", required=True)
    args = ap.parse_args()

    in_csv = Path(args.input_csv)
    out_json = Path(args.out_json)

    if not in_csv.is_file():
        raise SystemExit(f"FAIL: input CSV not found: {in_csv}")

    env = {
        "hostname": platform.node() or "unknown",
        "os": read_os_pretty(),
        "timezone": read_timezone(),
    }

    run_metadata: Dict[str, Any] = {
        "run_id": args.run_id,
        "timestamp_utc": args.timestamp_utc,
        "environment": env,
        "pipeline": {"name": args.pipeline_name, "version": args.pipeline_version},
        # extra fields are allowed (additionalProperties true):
        "generated_utc": utc_now_z(),
        "inputs": {
            "evtx_dir": str(Path(args.evtx_dir).resolve()),
            "timeline_csv": {
                "path": str(in_csv.resolve()),
                "sha256": sha256_file(in_csv),
                "size_bytes": in_csv.stat().st_size
            }
        },
        "source_tooling": {
            "hayabusa": {
                "version": args.hayabusa_version,
                "profile": args.profile
            }
        }
    }

    findings: List[Dict[str, Any]] = []
    requests: List[Dict[str, Any]] = []

    with in_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("FAIL: CSV has no header/fieldnames")
        rows = list(reader)

    for i, row in enumerate(rows, start=1):
        ts = get_col(row, "Timestamp")
        rule_title = get_col(row, "RuleTitle") or "Hayabusa hit"
        rule_id = get_col(row, "RuleID") or f"RAWREF:{in_csv.name}:row:{i}"
        severity = normalize_severity(get_col(row, "Level"))

        computer = get_col(row, "Computer")
        channel = get_col(row, "Channel")
        event_id = get_col(row, "EventID")
        record_id = get_col(row, "RecordID")
        evtx_file = get_col(row, "EvtxFile")

        # stable event reference strings
        event_ref = f"hayabusa:{in_csv.name}:row:{i}|computer={computer}|channel={channel}|event_id={event_id}|record_id={record_id}|evtx_file={evtx_file}"

        finding: Dict[str, Any] = {
            "finding_id": mk_finding_id(args.run_id, i),
            "category": category_from_mitre_tactics(row),
            "summary": rule_title[:280],
            "confidence": "medium",
            "severity": severity,
            "source": {
                "tool": "hayabusa",
                "rule_id": rule_id,
                "rule_title": rule_title,
                # extra provenance allowed:
                "profile": args.profile,
                "rule_file": get_col(row, "RuleFile") or None
            },
            "evidence": {
                "event_refs": [event_ref],
                "artifacts": [
                    {
                        "type": "event",
                        "ref": f"Computer={computer} Channel={channel} EventID={event_id} RecordID={record_id} EvtxFile={evtx_file}"
                    }
                ],
                "timestamps": {
                    "first_seen": ts or args.timestamp_utc,
                    "last_seen": ts or args.timestamp_utc
                },
                "raw": row
            },
            "raw_refs": [f"{in_csv.name}:row:{i}"]
        }

        findings.append(finding)

    doc = {
        "run_metadata": run_metadata,
        "findings": findings,
        "requests": requests
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"OK: wrote {out_json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

