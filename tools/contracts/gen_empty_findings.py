#!/usr/bin/env python3
import json
import os
import platform
import subprocess
import uuid
from datetime import datetime, timezone

def sh(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True).strip()

def get_os_string() -> str:
    try:
        # Ubuntu/SIFT-friendly
        return sh("lsb_release -ds").strip('"')
    except Exception:
        return platform.platform()

def get_timezone() -> str:
    try:
        return sh("timedatectl show -p Timezone --value")
    except Exception:
        return "UTC"

def main():
    pipeline_name = os.environ.get("DFIR_PIPELINE_NAME", "pipeline-undefined")
    pipeline_version = os.environ.get("DFIR_PIPELINE_VERSION", "0.0.0")

    doc = {
        "run_metadata": {
            "run_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "environment": {
                "hostname": sh("hostname"),
                "os": get_os_string(),
                "timezone": get_timezone()
            },
            "pipeline": {
                "name": pipeline_name,
                "version": pipeline_version
            }
        },
        "findings": [],
        "requests": []
    }

    print(json.dumps(doc, indent=2))

if __name__ == "__main__":
    main()
