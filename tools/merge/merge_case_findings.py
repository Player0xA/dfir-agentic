#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

FINDINGS_SCHEMA = Path("contracts/findings.schema.json")
FINDINGS_VALIDATOR = Path("tools/contracts/validate_findings.py")


def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(p: Path, obj: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def file_meta(p: Path) -> Dict[str, Any]:
    st = p.stat()
    return {
        "path": str(p),
        "sha256": sha256_file(p),
        "size_bytes": st.st_size,
    }


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
    tzfile = Path("/etc/timezone")
    if tzfile.is_file():
        try:
            tz = tzfile.read_text(encoding="utf-8", errors="ignore").strip()
            if tz:
                return tz
        except Exception:
            pass
    return "unknown"


def find_findings_path_from_manifest(manifest_path: Path) -> Path:
    """
    Expected:
      manifest.artifacts.findings_json.path
    If absent -> fail loudly.
    """
    m = load_json(manifest_path)
    artifacts = m.get("artifacts") or {}
    findings = artifacts.get("findings_json")
    if isinstance(findings, dict) and findings.get("path"):
        return Path(findings["path"])
    raise SystemExit(f"FAIL: manifest missing artifacts.findings_json.path: {manifest_path}")


def merge_requests(*docs: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for d in docs:
        reqs = d.get("requests") or []
        if not isinstance(reqs, list):
            continue
        for r in reqs:
            if not isinstance(r, dict):
                continue
            rid = r.get("request_id") or json.dumps(r, sort_keys=True)
            if rid in seen:
                continue
            seen.add(rid)
            out.append(r)
    return out


def finding_signature(f: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Deterministic dedupe signature (conservative):
      - tool
      - rule_id
      - normalized event_refs blob (or raw_refs fallback)
    """
    src = f.get("source") or {}
    tool = str(src.get("tool") or "")
    rule_id = str(src.get("rule_id") or "")

    ev = (f.get("evidence") or {}).get("event_refs") or []
    if isinstance(ev, list) and ev:
        ev_blob = "|".join(sorted(str(x) for x in ev))
    else:
        rr = f.get("raw_refs") or []
        ev_blob = "|".join(sorted(str(x) for x in rr)) if isinstance(rr, list) else ""

    return (tool, rule_id, ev_blob)


def attach_provenance(f: Dict[str, Any], origin: str, manifest_path: Path) -> Dict[str, Any]:
    out = dict(f)
    out["provenance"] = {
        "origin": origin,  # baseline|enrichment
        "manifest_path": str(manifest_path),
    }
    return out


def validate_findings(doc_path: Path) -> None:
    if not FINDINGS_SCHEMA.is_file():
        raise SystemExit(f"FAIL: findings schema not found: {FINDINGS_SCHEMA}")
    if not FINDINGS_VALIDATOR.is_file():
        raise SystemExit(f"FAIL: findings validator not found: {FINDINGS_VALIDATOR}")
    rc = os.system(f'{FINDINGS_VALIDATOR} "{FINDINGS_SCHEMA}" "{doc_path}"')
    if rc != 0:
        raise SystemExit(2)


def uuid4() -> str:
    import uuid
    return str(uuid.uuid4())


def main() -> int:
    ap = argparse.ArgumentParser(description="Merge baseline + enrichment findings into a single case findings contract")
    ap.add_argument("--intake-dir", required=True, help="outputs/intake/<intake_id>")
    ap.add_argument("--require-enrichment", action="store_true", help="fail if enrichment.json is missing OR not ok")
    ap.add_argument("--dedupe", action="store_true", help="dedupe within same tool/rule_id/event_refs")
    args = ap.parse_args()

    intake_dir = Path(args.intake_dir)
    if not intake_dir.is_dir():
        print(f"FAIL: intake dir not found: {intake_dir}", file=sys.stderr)
        return 2

    auto_path = intake_dir / "auto.json"
    if not auto_path.is_file():
        print(f"FAIL: auto.json not found: {auto_path}", file=sys.stderr)
        return 2

    auto = load_json(auto_path)
    intake_id = load_json(intake_dir / "intake.json").get("intake_id", "unknown") if (intake_dir / "intake.json").is_file() else "unknown"

    # --- baseline (required) ---
    baseline_manifest_path = Path(auto["dispatch"]["manifest_path"])
    if not baseline_manifest_path.is_file():
        print(f"FAIL: baseline manifest not found: {baseline_manifest_path}", file=sys.stderr)
        return 2

    baseline_findings_path = find_findings_path_from_manifest(baseline_manifest_path)
    if not baseline_findings_path.is_file():
        print(f"FAIL: baseline findings not found: {baseline_findings_path}", file=sys.stderr)
        return 2

    baseline_doc = load_json(baseline_findings_path)
    baseline_findings = baseline_doc.get("findings") or []
    if not isinstance(baseline_findings, list):
        print(f"FAIL: baseline findings doc has non-list findings: {baseline_findings_path}", file=sys.stderr)
        return 2

    # --- enrichment (agentic / optional) ---
    enrichment_path = intake_dir / "enrichment.json"
    have_enrichment_file = enrichment_path.is_file()

    if args.require_enrichment and not have_enrichment_file:
        print(f"FAIL: enrichment.json required but missing: {enrichment_path}", file=sys.stderr)
        return 2

    have_enrichment_ok = False
    enrichment_manifest_path: Optional[Path] = None
    enrichment_findings_path: Optional[Path] = None
    enrichment_findings: List[Dict[str, Any]] = []
    enrichment_findings_doc: Dict[str, Any] = {}

    if have_enrichment_file:
        enrichment_doc = load_json(enrichment_path)
        if not isinstance(enrichment_doc, dict):
            print(f"FAIL: enrichment.json is not an object: {enrichment_path}", file=sys.stderr)
            return 2

        result = enrichment_doc.get("result")
        if not isinstance(result, dict):
            print(f"FAIL: enrichment.json missing/invalid result object: {enrichment_path}", file=sys.stderr)
            return 2

        status = result.get("status")

        if status == "ok":
            mpath = result.get("manifest_path")
            if not mpath:
                print(f"FAIL: enrichment.json status=ok but missing result.manifest_path: {enrichment_path}", file=sys.stderr)
                return 2

            enrichment_manifest_path = Path(mpath)
            if not enrichment_manifest_path.is_file():
                print(f"FAIL: enrichment manifest not found: {enrichment_manifest_path}", file=sys.stderr)
                return 2

            enrichment_findings_path = find_findings_path_from_manifest(enrichment_manifest_path)
            if not enrichment_findings_path.is_file():
                print(f"FAIL: enrichment findings not found: {enrichment_findings_path}", file=sys.stderr)
                return 2

            enrichment_findings_doc = load_json(enrichment_findings_path)
            enrichment_findings = enrichment_findings_doc.get("findings") or []
            if not isinstance(enrichment_findings, list):
                print(f"FAIL: enrichment findings doc has non-list findings: {enrichment_findings_path}", file=sys.stderr)
                return 2

            have_enrichment_ok = True

        elif status in ("skipped", "denied"):
            # Valid agentic outcomes: nothing to merge.
            have_enrichment_ok = False

        else:
            print(f"FAIL: enrichment.json has unknown result.status={status!r}: {enrichment_path}", file=sys.stderr)
            return 2

    if args.require_enrichment and not have_enrichment_ok:
        print(f"FAIL: enrichment required but not ok (missing/skipped/denied): {enrichment_path}", file=sys.stderr)
        return 2

    # --- merge findings with provenance ---
    merged: List[Dict[str, Any]] = []
    seen = set()

    for f in baseline_findings:
        if not isinstance(f, dict):
            continue
        ff = attach_provenance(f, "baseline", baseline_manifest_path)
        if args.dedupe:
            sig = finding_signature(ff)
            if sig in seen:
                continue
            seen.add(sig)
        merged.append(ff)

    if have_enrichment_ok and enrichment_manifest_path is not None:
        for f in enrichment_findings:
            if not isinstance(f, dict):
                continue
            ff = attach_provenance(f, "enrichment", enrichment_manifest_path)
            if args.dedupe:
                sig = finding_signature(ff)
                if sig in seen:
                    continue
                seen.add(sig)
            merged.append(ff)

    # requests[] merge (baseline + enrichment-findings-doc only if ok)
    reqs = merge_requests(baseline_doc, enrichment_findings_doc if have_enrichment_ok else {})

    # --- output ---
    merge_run_id = uuid4()
    case_run_id = auto.get("selection", {}).get("run_id")  # optional

    # inputs: always include enrichment_json meta if file exists (audit), but only include manifest/findings meta if ok
    inputs_block: Dict[str, Any] = {
        "intake_dir": str(intake_dir),
        "auto_json": file_meta(auto_path),
        "baseline_manifest": file_meta(baseline_manifest_path),
        "baseline_findings": file_meta(baseline_findings_path),
    }

    if have_enrichment_file:
        inputs_block["enrichment_json"] = file_meta(enrichment_path)

    if have_enrichment_ok and enrichment_manifest_path and enrichment_findings_path:
        inputs_block["enrichment_manifest"] = file_meta(enrichment_manifest_path)
        inputs_block["enrichment_findings"] = file_meta(enrichment_findings_path)

    case_doc = {
        "run_metadata": {
            "run_id": merge_run_id,
            "timestamp_utc": utc_now_z(),
            "environment": {
                "hostname": platform.node() or "unknown",
                "os": read_os_pretty(),
                "timezone": read_timezone(),
            },
            "pipeline": {"name": "case-merge", "version": "0.1.0"},
            "inputs": inputs_block,
            "case_context": {
                "intake_id": intake_id,
                "baseline_pipeline": load_json(baseline_manifest_path).get("pipeline", {}),
                "has_enrichment": have_enrichment_ok,
                "enrichment_status": (load_json(enrichment_path).get("result", {}).get("status") if have_enrichment_file else None),
                "upstream_case_run_id": case_run_id,
            },
        },
        "findings": merged,
        "requests": reqs,
    }

    # --- Step 2: Generate the Markdown Index (The Map) ---
    severity_order = ["critical", "high", "medium", "low", "informational"]
    counts = {s: 0 for s in severity_order}
    
    findings_by_severity: Dict[str, List[Dict[str, Any]]] = {s: [] for s in severity_order}
    
    for f in merged:
        sev = (f.get("finding") or {}).get("severity", "informational").lower()
        if sev not in counts:
            sev = "informational"
        counts[sev] += 1
        findings_by_severity[sev].append(f)

    # Build Map
    md_lines = [
        f"# Case Investigation Summary: {intake_id}",
        f"**Timestamp**: {case_doc['run_metadata']['timestamp_utc']}",
        "",
        "## Situational Awareness (Metrics)",
    ]
    
    for s in severity_order:
        if counts[s] > 0:
            md_lines.append(f"- **{s.upper()}**: {counts[s]}")
    
    md_lines.extend([
        "",
        "## Top 15 High-Severity Findings (The Map)",
        "Use `dfir.query_findings@1` with the `finding_id` to surgically extract full evidence.",
        "",
        "| Severity | Tool | Rule | Finding ID |",
        "| :--- | :--- | :--- | :--- |"
    ])

    top_list = []
    for s in severity_order:
        top_list.extend(findings_by_severity[s])
        if len(top_list) >= 15:
            break
    top_list = top_list[:15]

    for f in top_list:
        sev = (f.get("finding") or {}).get("severity", "informational").upper()
        tool = (f.get("source") or {}).get("tool", "unknown")
        rule = (f.get("source") or {}).get("rule_id", "unknown")
        fid = f.get("finding_id", "unknown")
        md_lines.append(f"| {sev} | {tool} | {rule} | `{fid}` |")

    md_lines.extend([
        "",
        "> [!IMPORTANT]",
        "> Treat large tool outputs as data sources, not context. Do NOT read `case_findings.json` directly if it exceeds 100KB."
    ])

    out_case_summary_md = intake_dir / "case_summary.md"
    out_case_summary_md.write_text("\n".join(md_lines), encoding="utf-8")

    out_case_findings = intake_dir / "case_findings.json"
    write_json(out_case_findings, case_doc)

    case_manifest = {
        "run_id": merge_run_id,
        "timestamp_utc": case_doc["run_metadata"]["timestamp_utc"],
        "pipeline": case_doc["run_metadata"]["pipeline"],
        "status": "ok",
        "inputs": case_doc["run_metadata"]["inputs"],
        "artifacts": {
            "case_findings_json": file_meta(out_case_findings),
            "case_summary_md": file_meta(out_case_summary_md),
        },
    }
    out_case_manifest = intake_dir / "case_manifest.json"
    write_json(out_case_manifest, case_manifest)

    validate_findings(out_case_findings)

    print(f"OK: wrote {out_case_findings}")
    print(f"OK: wrote {out_case_summary_md}")
    print(f"OK: wrote {out_case_manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

