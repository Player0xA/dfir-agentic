import csv
import json
import argparse
import sys
from datetime import datetime, timezone

def generate_findings(input_csv, out_json, run_id, ts, mft_file):
    findings = []
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # MFTECmd fields to consider: EntryNumber, SequenceNumber, FileName, Created0x10, Extension, etc.
                entry = row.get('EntryNumber', '')
                filename = row.get('FileName', 'Unknown')
                created = row.get('Created0x10', 'Unknown')
                
                findings.append({
                    "version": "1.0",
                    "timestamp_utc": ts,
                    "pipeline": "mftecmd",
                    "run_id": run_id,
                    "evidence_id": "mft_file",
                    "evidence_refs": [mft_file],
                    "tool": {
                        "name": "MFTECmd",
                        "rule_title": "MFT File Entry",
                        "rule_id": "mft_entry"
                    },
                    "severity": "informational",
                    "confidence": "high",
                    "category": "File System",
                    "tactic": "TA0007", # Discovery (General File System Info)
                    "technique": "T1083",
                    "summary": f"File entry parsed from $MFT. Path/Name: {filename}",
                    "details": {
                        "FileName": filename,
                        "EntryNumber": entry,
                        "SequenceNumber": row.get('SequenceNumber', ''),
                        "ParentPath": row.get('ParentPath', ''),
                        "Extension": row.get('Extension', ''),
                        "FileSize": row.get('FileSize', ''),
                        "Created0x10": created,
                        "Created0x30": row.get('Created0x30', ''),
                        "LastModified0x10": row.get('LastModified0x10', ''),
                    },
                    "statement": f"File '{filename}' created at {created}."
                })
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "mftecmd",
        "pipeline_version": "0.1.0",
        "run_id": run_id,
        "input": {"csv": input_csv, "mft_file": mft_file},
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
    parser.add_argument('--mft-file', required=True)
    args = parser.parse_args()

    generate_findings(args.input_csv, args.out_json, args.run_id, args.timestamp_utc, args.mft_file)
