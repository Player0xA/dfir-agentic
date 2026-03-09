#!/usr/bin/env python3
import argparse
import sys
import pathlib
import json

# Add project root to path
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

from tools.case.case_manager import CaseManager

def main():
    parser = argparse.ArgumentParser(description="Import evidence into an authoritative forensic case.")
    parser.add_argument("--case-ref", required=True, help="Path to the authoritative case.json")
    parser.add_argument("--type", required=True, help="Evidence type (e.g., evtx, registry, plaso_file)")
    parser.add_argument("--src", required=True, help="Source path of the evidence")
    parser.add_argument("--dest", required=True, help="Destination relative path in staged/ root (e.g., evtx/Logs)")
    parser.add_argument("--id", help="Evidence ID (default: dest part)")
    parser.add_argument("--stage", choices=["symlink", "copy"], default="symlink", help="Staging method (default: symlink)")
    
    args = parser.parse_args()
    
    case_json = pathlib.Path(args.case_ref).resolve()
    if not case_json.exists():
        print(f"[FAIL] Case metadata not found: {case_json}")
        sys.exit(1)
        
    case_root = case_json.parent
    cm = CaseManager(case_root)
    
    evidence_id = args.id or args.dest.replace("/", "_").replace("\\", "_")
    
    print(f"[*] Importing evidence '{args.src}' into case...")
    try:
        item = cm.add_evidence(
            source_path=args.src,
            evidence_id=evidence_id,
            artifact_type=args.type,
            relpath=args.dest
        )
        print(f"[SUCCESS] Evidence imported.")
        print(f"Logical ID: {item['evidence_id']}")
        print(f"Staged Path: {case_root}/evidence/staged/{item['relpath']}")
    except Exception as e:
        print(f"[FAIL] Failed to import evidence: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
