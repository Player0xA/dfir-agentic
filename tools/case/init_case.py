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
    parser = argparse.ArgumentParser(description="Initialize a deterministic forensic case layout.")
    parser.add_argument("--case-id", required=True, help="Unique identifier for the case (e.g., mills-sqlserver-2026-01)")
    parser.add_argument("--root", required=True, help="Base directory where the case will be created")
    
    args = parser.parse_args()
    
    case_path = pathlib.Path(args.root) / args.case_id
    cm = CaseManager(case_path)
    
    print(f"[*] Initializing case '{args.case_id}' at {case_path}...")
    try:
        case_meta = cm.init_case(args.case_id)
        print(f"[SUCCESS] Case initialized.")
        print(f"Authoritative metadata: {case_path}/case.json")
    except Exception as e:
        print(f"[FAIL] Failed to initialize case: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
