import csv
import json
import argparse
import sys
from datetime import datetime, timezone

def generate_findings(input_csv, out_json, run_id, ts, target_path):
    findings = []
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # LECmd fields: SourceFile, TargetExecutionPath, TargetCreationTime, VolumeName, LocalPath, etc.
                source_file = row.get('SourceFile', 'Unknown')
                target_path_lnk = row.get('TargetExecutionPath', row.get('LocalPath', 'Unknown'))
                target_created = row.get('TargetCreationTime', 'Unknown')
                
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "lecmd",
                    "run_id": run_id,
                    "evidence_id": "lnk_file",
                    "evidence_refs": [target_path],
                    "tool": {
                        "name": "LECmd",
                        "rule_title": "Shortcut (LNK) Entry",
                        "rule_id": "lnk_entry"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "File System / Execution",
                    "tactic": "TA0002", # Execution
                    "technique": "T1204.002", # User Execution: Malicious File (LNK)
                    "summary": f"Shortcut (LNK) file parsed. Target: {target_path_lnk}",
                    "details": {
                        "SourceFile": source_file,
                        "TargetExecutionPath": target_path_lnk,
                        "TargetCreationTime": target_created,
                        "TargetModificationTime": row.get('TargetModificationTime', ''),
                        "TargetAccessTime": row.get('TargetAccessTime', ''),
                        "Arguments": row.get('Arguments', ''),
                        "IconLocation": row.get('IconLocation', ''),
                        "VolumeName": row.get('VolumeName', ''),
                        "DriveType": row.get('DriveType', ''),
                    },
                    "statement": f"Shortcut '{source_file}' pointing to '{target_path_lnk}' was parsed."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "lecmd",
        "pipeline_version": "0.1.0",
        "run_id": run_id,
        "input": {"csv": input_csv, "target_path": target_path},
        "findings": findings
    }

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(out_data, f, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-csv', required=True)
    parser.add_argument('--out-json', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--timestamp-utc', required=True)
    parser.add_argument('--target-path', required=True)
    args = parser.parse_args()

    generate_findings(args.input_csv, args.out_json, args.run_id, args.timestamp_utc, args.target_path)
