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
                # RBCmd fields: SourceName, SourcePath, FileName, FileSize, DeletedOn
                file_name = row.get('FileName', 'Unknown')
                deleted_on = row.get('DeletedOn', 'Unknown')
                
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "rbcmd",
                    "run_id": run_id,
                    "evidence_id": "recycle_bin",
                    "evidence_refs": [target_path],
                    "tool": {
                        "name": "RBCmd",
                        "rule_title": "Recycle Bin Entry",
                        "rule_id": "recycle_bin_entry"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "File System / Deletion",
                    "tactic": "TA0007", # Discovery / TA0005 Defense Evasion (File Deletion)
                    "technique": "T1070.004", # File Deletion
                    "summary": f"File deleted to Recycle Bin. Original Name: {file_name}",
                    "details": {
                        "FileName": file_name,
                        "FileSize": row.get('FileSize', ''),
                        "DeletedOn": deleted_on,
                        "SourcePath": row.get('SourcePath', ''),
                        "SourceName": row.get('SourceName', '')
                    },
                    "statement": f"File '{file_name}' was deleted to the Recycle Bin on {deleted_on}."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "rbcmd",
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
