#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import uuid
import re
from datetime import datetime, timezone
from typing import List, Tuple, Optional

DISK_IMAGE_EXT = {".e01", ".ex01", ".aff", ".aff4", ".dd", ".img", ".raw"}
PCAP_EXT = {".pcap", ".pcapng"}
MEM_EXT = {".mem", ".rawmem", ".dmp", ".dd"}

def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize_case_name(name: str) -> str:
    """Convert a friendly case name to a safe directory name."""
    # Remove or replace unsafe characters
    safe = re.sub(r'[^\w\s-]', '', name)
    # Replace spaces with hyphens
    safe = re.sub(r'\s+', '-', safe)
    # Remove multiple consecutive hyphens
    safe = re.sub(r'-+', '-', safe)
    # Trim and lowercase
    safe = safe.strip('-').lower()
    # If empty, use timestamp
    if not safe:
        safe = f"case-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    return safe

def generate_case_name_suggestion(paths: List[str], classification_kind: str) -> str:
    """Auto-suggest a case name based on evidence."""
    timestamp = datetime.now().strftime('%Y%m%d')
    
    # Try to extract a hostname or meaningful name from the first path
    first_path = paths[0] if paths else "unknown"
    base_name = os.path.basename(first_path.rstrip('/'))
    
    # Clean up the base name
    clean_base = base_name.replace('.evtx', '').replace('.mem', '').replace('.dmp', '')
    clean_base = re.sub(r'[^\w-]', '', clean_base)[:20]  # Limit length
    
    # Add classification type
    type_map = {
        'windows_triage_dir': 'windows',
        'windows_evtx_dir': 'evtx',
        'memory_dump_file': 'memory',
        'disk_image_file': 'disk',
        'pcap_file': 'network',
        'linux_logs_dir': 'linux'
    }
    type_prefix = type_map.get(classification_kind, 'case')
    
    if clean_base:
        return f"{clean_base}-{type_prefix}-{timestamp}"
    else:
        return f"{type_prefix}-{timestamp}"

def is_evtx_file(p: pathlib.Path) -> bool:
    return p.is_file() and p.suffix.lower() in {".evtx", ".evt"}

def probe_magic(p: pathlib.Path) -> Tuple[Optional[str], Optional[str]]:
    """
    Phase 47: Deterministic Evidence Probing
    Reads the head of the file to identify known magic bytes/structures.
    Returns (kind, signature_name).
    """
    try:
        with p.open("rb") as f:
            head = f.read(4096)
            
        if not head:
            return None, None

        # Memory Dump Signatures
        # LiME (Linux Memory Extractor): "EMiL"
        if head.startswith(b"EMiL"):
            return "memory_dump_file", "lime_magic_detected"
        
        # Windows Crash Dump (64-bit): "PAGE" or "MDMP"
        if head.startswith(b"PAGE") or head.startswith(b"MDMP"):
            return "memory_dump_file", "crashdump_magic_detected"

        # AVML (Acquire Volatile Memory for Linux): AVML signature in ELF note or header
        if head.startswith(b"\x7fELF") and b"AVML" in head:
            return "memory_dump_file", "avml_magic_detected"

        # Disk Image Signatures
        # Raw disk with GPT (EFI PART at offset 512)
        if len(head) >= 1024 and head[512:520] == b"EFI PART":
            return "disk_image_file", "gpt_partition_magic_detected"

        # Raw disk with MBR (Boot signature 0x55 0xAA at offset 510)
        # We must be careful not to mistake a random file for MBR, so we also check
        # common boot code heuristics or just accept it as a weak signal.
        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            # Check for common MBR boot code (e.g., GRUB, Windows MBR)
            # or an active partition flag (0x80) at offset 446
            if head[446] in (0x00, 0x80):
                return "disk_image_file", "mbr_partition_magic_detected"

        # PCAPNG
        if head.startswith(b"\x0a\x0d\x0d\x0a"):
            return "pcap_file", "pcapng_magic_detected"

        # PCAP (Magic 0xa1b2c3d4 or 0xd4c3b2a1)
        if head.startswith(b"\xa1\xb2\xc3\xd4") or head.startswith(b"\xd4\xc3\xb2\xa1"):
            return "pcap_file", "pcap_magic_detected"

    except Exception:
        pass
        
    return None, None

def classify_path(p: pathlib.Path) -> Tuple[str, List[str], str, Optional[str]]:
    signals: List[str] = []

    if not p.exists():
        return ("unknown", [f"path_not_found:{str(p)}"], "low", None)

    if p.is_dir():
        # First, check for structural Windows triage characteristics
        triage_signals = []
        if (p / "Windows/System32/config").exists() or (p / "Windows/System32/winevt").exists():
            triage_signals.append("windows_system_folder_detected")
        if (p / "$MFT").exists():
            triage_signals.append("mft_detected")
        if (p / "Users").exists() and any(p.rglob("NTUSER.DAT")):
            triage_signals.append("ntuser_dat_detected")
        if any(p.rglob("SYSTEM")) and any(p.rglob("SOFTWARE")):
            triage_signals.append("registry_hives_detected")
            
        if triage_signals:
            return ("windows_triage_dir", triage_signals, "high", "plaso_evtx")

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
    
    # Phase 47: Magic Signature Probing
    magic_kind, sig_name = probe_magic(p)
    if magic_kind:
        if sig_name:
            signals.append(sig_name)
        if magic_kind == "memory_dump_file":
            # Extra signal if extension matches, but trust magic as HIGH
            if ext in MEM_EXT:
                signals.append(f"file_extension_memory_dump:{ext}")
            return ("memory_dump_file", signals, "high", None)
            
        if magic_kind == "disk_image_file":
            if ext in DISK_IMAGE_EXT:
                signals.append(f"file_extension_disk_image:{ext}")
            return ("disk_image_file", signals, "high", None)
            
        if magic_kind == "pcap_file":
            return ("pcap_file", signals, "high", None)

    # Fallback to pure extension-based heuristics (medium/low confidence)
    if ext in PCAP_EXT:
        signals.append(f"file_extension_pcap:{ext}")
        return ("pcap_file", signals, "medium", None)

    if ext in MEM_EXT:
        signals.append(f"file_extension_memory_dump:{ext}")
        return ("memory_dump_file", signals, "medium", None)

    if ext in DISK_IMAGE_EXT:
        signals.append(f"file_extension_disk_image:{ext}")
        return ("disk_image_file", signals, "medium", None)

    return ("unknown", ["file_no_known_signals"], "low", None)

def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic evidence identification")
    ap.add_argument("paths", nargs="+", help="one or more evidence paths (file or dir)")
    ap.add_argument("--out-base", default="outputs/intake", help="base output directory")
    ap.add_argument("--case-name", help="Friendly case name (will be sanitized for directory)")
    ap.add_argument("--display-name", help="Display name for the case (if different from case-name)")
    args = ap.parse_args()

    # Generate internal intake_id (UUID for tracking)
    intake_id = str(uuid.uuid4())
    ts = utc_now_z()

    # If multiple paths: pick the highest-confidence result, but record all signals
    results = []
    all_signals: List[str] = []
    for s in args.paths:
        p = pathlib.Path(s).expanduser()
        kind, signals, conf, rec = classify_path(p)
        results.append((kind, conf, rec or "", str(p), signals))
        for sig in signals:
            all_signals.append(f"{os.path.basename(str(p))}:{sig}")

    conf_rank = {"high": 0, "medium": 1, "low": 2}
    # choose best (deterministic sort) - handle None values in rec by converting to empty string
    best = sorted(results, key=lambda r: (conf_rank.get(r[1], 9), r[0], r[3] or ""))[0]
    best_kind, best_conf, best_rec, best_path, _best_signals = best

    # Determine case naming
    if args.case_name:
        # User provided a case name - sanitize it for directory
        dir_name = sanitize_case_name(args.case_name)
        display_name = args.display_name or args.case_name
    else:
        # Auto-generate case name based on evidence
        suggested = generate_case_name_suggestion(args.paths, best_kind)
        dir_name = sanitize_case_name(suggested)
        display_name = suggested

    # Ensure unique directory name by appending intake_id suffix if needed
    out_dir = pathlib.Path(args.out_base) / dir_name
    counter = 1
    original_dir_name = dir_name
    while out_dir.exists():
        dir_name = f"{original_dir_name}-{counter}"
        out_dir = pathlib.Path(args.out_base) / dir_name
        counter += 1

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "intake.json"

    doc = {
        "intake_id": intake_id,
        "case_name": dir_name,  # Directory name (sanitized)
        "display_name": display_name,  # Human-readable display name
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
