import csv
import json
import argparse
import sys
from datetime import datetime, timezone

def generate_findings(input_csv, out_json, run_id, ts, system_hive):
    findings = []
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "appcompatcache",
                    "run_id": run_id,
                    "evidence_id": "system_hive",
                    "evidence_refs": [system_hive],
                    "tool": {
                        "name": "AppCompatCacheParser",
                        "rule_title": "AppCompatCache Entry",
                        "rule_id": "appcompat_cache"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "Execution",
                    "tactic": "TA0002",
                    "technique": "T1059",
                    "summary": f"Execution parsed from AppCompatCache. Path: {row.get('Path', 'Unknown')}",
                    "details": {
                        "Path": row.get('Path'),
                        "LastModifiedTimeUTC": row.get('LastModifiedTimeUTC'),
                        "Executed": row.get('Executed')
                    },
                    "statement": f"Evidence of execution for {row.get('Path', 'Unknown')} at {row.get('LastModifiedTimeUTC', 'Unknown')}."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "appcompatcache",
        "pipeline_version": "0.1.0",
        "run_id": run_id,
        "input": {"csv": input_csv, "system_hive": system_hive},
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
    parser.add_argument('--system-hive', required=True)
    args = parser.parse_args()

    generate_findings(args.input_csv, args.out_json, args.run_id, args.timestamp_utc, args.system_hive)
