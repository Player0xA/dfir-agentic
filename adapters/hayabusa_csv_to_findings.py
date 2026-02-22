#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def now_utc_z() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def die(msg: str, code: int = 2) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


def get_col(row: Dict[str, str], key: str) -> str:
    # CSV DictReader returns "" for empty cells; key might not exist if profile differs.
    return (row.get(key) or "").strip()


def mk_finding_id(run_id: str, n: int) -> str:
    # Matches your existing style: F-<runid>-000001
    return f"F-{run_id}-{n:06d}"


def split_tags(s: str) -> List[str]:
    s = (s or "").strip()
    if not s or s == "-":
        return []
    # Hayabusa typically uses commas; sometimes pipes appear in details fields.
    # Normalize both.
    parts: List[str] = []
    for chunk in s.replace("|", ",").split(","):
        t = chunk.strip()
        if t:
            parts.append(t)
    # stable order (do not sort; keep original)
    return parts


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Hayabusa csv-timeline output into dfir-agentic findings.json")
    ap.add_argument("--input-csv", required=True, help="Path to Hayabusa timeline CSV")
    ap.add_argument("--out-json", required=True, help="Output findings.json path")
    ap.add_argument("--run-id", required=True, help="Deterministic run_id (UUID or your run id)")
    ap.add_argument("--evtx-dir", required=True, help="EVTX directory scanned (for provenance)")
    ap.add_argument("--profile", default="verbose", help="Hayabusa profile used (for provenance)")
    args = ap.parse_args()

    in_csv = Path(args.input_csv)
    out_json = Path(args.out_json)

    if not in_csv.is_file():
        die(f"input CSV not found: {in_csv}")

    # Read CSV
    with in_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            die("CSV has no header/fieldnames")

        rows = list(reader)

    findings: List[Dict[str, Any]] = []
    for i, row in enumerate(rows, start=1):
        ts = get_col(row, "Timestamp")
        rule_title = get_col(row, "RuleTitle")
        level = get_col(row, "Level").lower()
        computer = get_col(row, "Computer")
        channel = get_col(row, "Channel")
        event_id = get_col(row, "EventID")
        record_id = get_col(row, "RecordID")

        details = get_col(row, "Details")
        extra = get_col(row, "ExtraFieldInfo")

        # Only present in verbose/super-verbose profiles:
        mitre_tactics = split_tags(get_col(row, "MitreTactics"))
        mitre_tags = split_tags(get_col(row, "MitreTags"))
        other_tags = split_tags(get_col(row, "OtherTags"))

        rule_id = get_col(row, "RuleID")
        rule_file = get_col(row, "RuleFile")
        evtx_file = get_col(row, "EvtxFile")

        # Minimal normalization: Hayabusa levels are already meaningful.
        # Keep as-is; your findings validator can enforce allowed enums.
        severity = level if level else "informational"

        finding: Dict[str, Any] = {
            "finding_id": mk_finding_id(args.run_id, i),
            "timestamp": ts,  # already ISO8601 Z when you run with -O
            "severity": severity,
            "rule_title": rule_title,
            "rule_id": rule_id,
            "host": {
                "computer": computer,
            },
            "event": {
                "channel": channel,
                "event_id": int(event_id) if event_id.isdigit() else event_id,
                "record_id": int(record_id) if record_id.isdigit() else record_id,
            },
            "mitre": {
                "tactics": mitre_tactics,
                "tags": mitre_tags,
            },
            "tags": other_tags,
            "details": {
                "details": details,
                "extra": extra,
            },
            "source": {
                "tool": "hayabusa",
                "tool_profile": args.profile,
                "evtx_dir": str(Path(args.evtx_dir)),
                "timeline_csv": str(in_csv),
                "rule_file": rule_file,
                "evtx_file": evtx_file,
            },
        }

        findings.append(finding)

    # Envelope (keeps provenance + stable structure)
    doc: Dict[str, Any] = {
        "generated_utc": now_utc_z(),
        "run_id": args.run_id,
        "pipeline": "hayabusa_evtx",
        "inputs": {
            "evtx_dir": str(Path(args.evtx_dir)),
            "timeline_csv": str(in_csv),
        },
        "counts": {
            "total_findings": len(findings),
        },
        "findings": findings,
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"OK: wrote {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

