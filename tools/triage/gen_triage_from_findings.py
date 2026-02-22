#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEV_RANK = {
    # deterministic ordering for "top findings"
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 5,
    None: 6,
}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def get_ts(obj: Dict[str, Any], key: str) -> Optional[str]:
    # obj["evidence"]["timestamps"]["first_seen"] etc
    try:
        v = obj["evidence"]["timestamps"].get(key)
        return v if isinstance(v, str) else None
    except Exception:
        return None

def sev_rank(sev: Optional[str]) -> int:
    if sev is None:
        return SEV_RANK[None]
    s = str(sev).strip().lower()
    if s == "info":
        s = "informational"
    return SEV_RANK.get(s, 5)

def normalize_sev_key(sev: Any) -> str:
    if isinstance(sev, str):
        s = sev.strip().lower()
        if s == "info":
            return "informational"
        return s if s else "unknown"
    return "unknown"

def main() -> int:
    ap = argparse.ArgumentParser(description="Generate deterministic triage.json from findings.json")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--timestamp-utc", required=True)
    ap.add_argument("--pipeline-name", required=True)
    ap.add_argument("--pipeline-version", required=True)
    ap.add_argument("--findings-json", required=True)
    ap.add_argument("--output-json", required=True)
    ap.add_argument("--top-n", type=int, default=25)
    args = ap.parse_args()

    findings_path = Path(args.findings_json)
    out_path = Path(args.output_json)

    data = json.loads(findings_path.read_text(encoding="utf-8"))

    # Accept either {"findings":[...]} or direct array (be permissive but deterministic)
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise SystemExit("FAIL: findings.json must be a list or an object with key 'findings'")

    by_sev: Dict[str, int] = {}
    by_rule: Dict[Tuple[str, Optional[str]], int] = {}

    min_first: Optional[str] = None
    max_last: Optional[str] = None

    # Flatten minimal fields for top list
    minimal: List[Dict[str, Optional[str]]] = []

    for f in findings:
        if not isinstance(f, dict):
            continue

        sev = f.get("severity")
        sev_key = normalize_sev_key(sev)
        by_sev[sev_key] = by_sev.get(sev_key, 0) + 1

        rule_id = None
        rule_title = None
        try:
            src = f.get("source") or {}
            rule_id = src.get("rule_id")
            rule_title = src.get("rule_title")
        except Exception:
            pass

        rid = str(rule_id) if isinstance(rule_id, str) else "null"
        title_norm = rule_title if isinstance(rule_title, str) else None
        by_rule[(rid, title_norm)] = by_rule.get((rid, title_norm), 0) + 1

        first_seen = get_ts(f, "first_seen")
        last_seen = get_ts(f, "last_seen")

        # time bounds (lexical compare is OK for ISO timestamps with timezone)
        if first_seen:
            if min_first is None or first_seen < min_first:
                min_first = first_seen
        if last_seen:
            if max_last is None or last_seen > max_last:
                max_last = last_seen

        minimal.append({
            "finding_id": f.get("finding_id"),
            "severity": sev if isinstance(sev, str) else None,
            "rule_id": rule_id if isinstance(rule_id, str) else None,
            "rule_title": rule_title if isinstance(rule_title, str) else None,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "summary": f.get("summary") if isinstance(f.get("summary"), str) else None,
        })

    # Deterministic totls + hard guardrail
    total_findings = len(findings)
    by_sev_sum = sum(by_sev.values())
    if by_sev_sum != total_findings:
        raise SystemExit(
            f"FAIL: triage counts mismatch: by_severity sum != total_findings ({by_sev_sum} != {total_findings})"
        )

    # Deterministic top findings selection
    # Sort: severity rank -> first_seen -> finding_id
    minimal_sorted = sorted(
        minimal,
        key=lambda x: (
            sev_rank(x.get("severity")),
            x.get("first_seen") or "",
            x.get("finding_id") or "",
        ),
    )
    top = minimal_sorted[: max(0, args.top_n)]

    # Deterministic by_rule output: sort by count desc, then rule_id asc, then title asc
    by_rule_rows = []
    for (rid, title), cnt in by_rule.items():
        by_rule_rows.append({
            "rule_id": rid,
            "rule_title": title,
            "count": cnt
        })
    by_rule_rows.sort(key=lambda r: (-r["count"], r["rule_id"], r["rule_title"] or ""))

    triage = {
        "run_id": args.run_id,
        "timestamp_utc": args.timestamp_utc,
        "pipeline": {"name": args.pipeline_name, "version": args.pipeline_version},
        "source_findings": {
            "path": str(findings_path),
            "sha256": sha256_file(findings_path),
            "size": findings_path.stat().st_size,
            "count": total_findings,
        },
        "time_bounds": {
            "min_first_seen": min_first,
            "max_last_seen": max_last,
        },
        "counts": {
            "total_findings": total_findings,
            "by_severity": dict(sorted(by_sev.items(), key=lambda kv: kv[0])),
            "by_rule_id": by_rule_rows,
        },
        "top_findings": top,
    }

    out_path.write_text(json.dumps(triage, indent=2), encoding="utf-8")
    print(f"OK: wrote {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

