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
                # JLECmd fields: SourceFile, TargetIDAbsolutePath, TargetCreationTime, TargetModificationTime, LocalPath
                source_file = row.get('SourceFile', 'Unknown')
                target_path_lnk = row.get('TargetIDAbsolutePath', row.get('LocalPath', 'Unknown'))
                
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "jlecmd",
                    "run_id": run_id,
                    "evidence_id": "jump_list",
                    "evidence_refs": [target_path],
                    "tool": {
                        "name": "JLECmd",
                        "rule_title": "Jump List Entry",
                        "rule_id": "jump_list_entry"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "File System / Execution",
                    "tactic": "TA0002", # Execution
                    "technique": "T1204.002", # User Execution
                    "summary": f"Jump List execution entry for: {target_path_lnk}",
                    "details": {
                        "SourceFile": source_file,
                        "TargetExecutionPath": target_path_lnk,
                        "TargetCreationTime": row.get('TargetCreationTime', ''),
                        "TargetModificationTime": row.get('TargetModificationTime', ''),
                        "TargetAccessTime": row.get('TargetAccessTime', ''),
                        "Arguments": row.get('Arguments', ''),
                        "AppId": row.get('AppId', ''),
                        "AppIdDescription": row.get('AppIdDescription', '')
                    },
                    "statement": f"Jump List '{source_file}' contained an entry pointing to '{target_path_lnk}'."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "jlecmd",
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
