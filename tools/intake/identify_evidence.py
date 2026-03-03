#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import uuid
from datetime import datetime, timezone
from typing import List, Tuple, Optional

DISK_IMAGE_EXT = {".e01", ".ex01", ".aff", ".aff4", ".dd", ".img", ".raw"}
PCAP_EXT = {".pcap", ".pcapng"}
MEM_EXT = {".mem", ".rawmem", ".dmp", ".dd"}

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_evtx_file(p: pathlib.Path) -> bool:
    return p.is_file() and p.suffix.lower() in {".evtx", ".evt"}

def classify_path(p: pathlib.Path) -> Tuple[str, List[str], str, Optional[str]]:
    signals: List[str] = []

    if not p.exists():
        return ("unknown", [f"path_not_found:{str(p)}"], "low", None)

    if p.is_dir():
        evtx = sorted([str(x) for x in p.rglob("*.evtx")])
        evt = sorted([str(x) for x in p.rglob("*.evt")])
        if evtx or evt:
            signals.append(f"dir_contains_evtx_count:{len(evtx)}")
            signals.append(f"dir_contains_evt_count:{len(evt)}")
            # extra strong signal
            if any(pathlib.Path(x).name.lower() == "security.evtx" for x in evtx):
                signals.append("security_evtx_present")
            return ("windows_evtx_dir", signals, "high", "chainsaw_evtx")

        # minimal linux logs heuristic (kept conservative)
        common = ["var/log", "auth.log", "syslog", "messages", "secure", "journal"]
        hits = 0
        for c in common:
            if (p / c).exists():
                hits += 1
        if hits >= 1:
            signals.append(f"linux_log_signal_hits:{hits}")
            return ("linux_logs_dir", signals, "medium", None)

        return ("unknown", ["dir_no_known_signals"], "low", None)

    # file case
    if is_evtx_file(p):
        signals.append("file_extension_evtx_or_evt")
        return ("windows_evtx_file", signals, "high", "chainsaw_evtx")

    ext = p.suffix.lower()
    if ext in PCAP_EXT:
        signals.append(f"file_extension_pcap:{ext}")
        return ("pcap_file", signals, "high", None)

    if ext in MEM_EXT:
        signals.append(f"file_extension_memory_dump:{ext}")
        return ("memory_dump_file", signals, "medium", None)

    if ext in DISK_IMAGE_EXT:
        signals.append(f"file_extension_disk_image:{ext}")
        return ("disk_image_file", signals, "medium", None)

    # lightweight magic check (no external deps): read first bytes for pcapng
    try:
        with p.open("rb") as f:
            head = f.read(16)
        # pcapng section header block magic (0x0A0D0D0A)
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            signals.append("pcapng_magic_detected")
            return ("pcap_file", signals, "medium", None)
    except Exception:
        pass

    return ("unknown", ["file_no_known_signals"], "low", None)

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic evidence identification")
    ap.add_argument("paths", nargs="+", help="one or more evidence paths (file or dir)")
    ap.add_argument("--out-base", default="outputs/intake", help="base output directory")
    args = ap.parse_args()

    intake_id = str(uuid.uuid4())
    ts = utc_now_z()

    # If multiple paths: pick the highest-confidence result, but record all signals
    results = []
    all_signals: List[str] = []
    for s in args.paths:
        p = pathlib.Path(s).expanduser()
        kind, signals, conf, rec = classify_path(p)
        results.append((kind, conf, rec, str(p), signals))
        for sig in signals:
            all_signals.append(f"{os.path.basename(str(p))}:{sig}")

    conf_rank = {"high": 0, "medium": 1, "low": 2}
    # choose best (deterministic sort)
    best = sorted(results, key=lambda r: (conf_rank.get(r[1], 9), r[0], r[3]))[0]
    best_kind, best_conf, best_rec, best_path, _best_signals = best

    out_dir = pathlib.Path(args.out_base) / intake_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "intake.json"

    doc = {
        "intake_id": intake_id,
        "timestamp_utc": ts,
        "inputs": {"paths": [str(pathlib.Path(p).expanduser()) for p in args.paths]},
        "classification": {
            "kind": best_kind,
            "confidence": best_conf,
            "recommended_pipeline": best_rec
        },
        "signals": all_signals
    }

    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"OK: wrote {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

