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
                # RecentFileCacheParser fields: TargetPath
                target_exec = row.get('TargetPath', 'Unknown')
                
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "recentfilecache",
                    "run_id": run_id,
                    "evidence_id": "recentfilecache",
                    "evidence_refs": [target_path],
                    "tool": {
                        "name": "RecentFileCacheParser",
                        "rule_title": "Application Compatibility Cache Entry",
                        "rule_id": "recentfilecache_entry"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "Execution / Application Compatibility",
                    "tactic": "TA0002", # Execution
                    "technique": "T1204.002", # User Execution: Malicious File
                    "summary": f"RecentFileCache entry indicating execution of: {target_exec}",
                    "details": {
                        "TargetExecutionPath": target_exec
                    },
                    "statement": f"Application Compatibility caching recorded the existence/execution of '{target_exec}'."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "recentfilecache",
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
