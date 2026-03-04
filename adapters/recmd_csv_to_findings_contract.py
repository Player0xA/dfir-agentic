import csv
import json
import argparse
import sys
import os

def generate_findings(input_csv, out_json, run_id, ts, target_path):
    findings = []
    
    if not os.path.exists(input_csv):
        # Empty execution
        pass
    else:
        try:
            with open(input_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # RECmd fields depending on plugins or generic search
                    # Standard key fields: HivePath, KeyPath, ValueName, ValueData, LastWriteTimestamp
                    key_path = row.get('KeyPath', 'Unknown')
                    value_name = row.get('ValueName', '')
                    value_data = row.get('ValueData', '')
                    
                    details = {
                        "HivePath": row.get('HivePath', ''),
                        "KeyPath": key_path,
                        "ValueName": value_name,
                        "ValueType": row.get('ValueType', ''),
                    }
                    if value_data:
                        details["ValueData"] = value_data
                    if 'LastWriteTimestamp' in row:
                        details["LastWriteTimestamp"] = row.get('LastWriteTimestamp')
                        
                    summary_msg = f"Registry key: {key_path}"
                    if value_name:
                        summary_msg += f" \ {value_name}"

                    findings.append({
                        "version": "1.0",
                        "timestamp_utc": ts,
                        "pipeline": "recmd",
                        "run_id": run_id,
                        "evidence_id": "registry_hive",
                        "evidence_refs": [target_path],
                        "tool": {
                            "name": "RECmd",
                            "rule_title": "Registry Hive Entry",
                            "rule_id": "registry_entry"
                        },
                        "severity": "informational",
                        "confidence": "high",
                        "category": "Operating System",
                        "tactic": "TA0007", # Discovery (General Config)
                        "technique": "T1012", # Query Registry
                        "summary": summary_msg,
                        "details": details,
                        "statement": f"Registry configuration found: {summary_msg}"
                    })
        except Exception as e:
            print(f"Error parsing CSV {input_csv}: {e}", file=sys.stderr)
            # We don't exit 1 here, just record what we have or an empty finding list
            pass

    out_data = {
        "timestamp_utc": ts,
        "pipeline_name": "recmd",
        "pipeline_version": "2.1.0",
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
