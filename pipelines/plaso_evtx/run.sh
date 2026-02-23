#!/bin/bash
set -e

# Plaso Pipeline Runner for dfir-agentic
# Generates a .plaso super timeline from an EVTX directory.

RUN_ID="${1}"
TS_UTC="${2}"
EVTX_DIR="${3}"
# Expand tilde if present
if [[ "${EVTX_DIR}" == "~"* ]]; then
  EVTX_DIR="${EVTX_DIR/#\~/$HOME}"
fi
OUT_ROOT="${4:-outputs/plaso_evtx}"

L2T_BIN="${L2T_BIN:-log2timeline.py}"
PLASO_DIR="${OUT_ROOT}/${RUN_ID}"
PLASO_FILE="${PLASO_DIR}/case.plaso"
REQUEST_JSON="${PLASO_DIR}/request.json"
MANIFEST_JSON="${PLASO_DIR}/manifest.json"

mkdir -p "${PLASO_DIR}"

echo "INFO: Generating Plaso timeline"
echo "  RUN_ID:   ${RUN_ID}"
echo "  EVTX_DIR: ${EVTX_DIR}"
echo "  OUT_FILE: ${PLASO_FILE}"

# 1. Audit Request
cat <<EOF > "${REQUEST_JSON}"
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "plaso_evtx",
  "run_id": "${RUN_ID}",
  "evtx_dir": "${EVTX_DIR}",
  "plaso": {
    "bin": "${L2T_BIN}",
    "storage_file": "${PLASO_FILE}"
  }
}
EOF

# 2. Run log2timeline
"${L2T_BIN}" --storage-file "${PLASO_FILE}" "${EVTX_DIR}"

# 3. Generate Manifest
python3 - <<PY > "${MANIFEST_JSON}"
import os, json, hashlib, pathlib

def sha256(p: str) -> str:
    if not os.path.exists(p): return "null"
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fmeta(p: str):
    if not os.path.exists(p): return None
    st = os.stat(p)
    return {"path": p, "sha256": sha256(p), "size": st.st_size}

manifest = {
  "run_id": ${RUN_ID@Q},
  "timestamp_utc": ${TS_UTC@Q},
  "pipeline": {"name": "plaso_evtx", "version": "0.1.0"},
  "status": "ok",
  "inputs": {
    "evtx_dir": ${EVTX_DIR@Q}
  },
  "tooling": {
    "plaso": {
      "path": ${L2T_BIN@Q}
    }
  },
  "artifacts": {
    "request_json": fmeta(${REQUEST_JSON@Q}),
    "plaso_file": fmeta(${PLASO_FILE@Q}),
    "manifest_json": fmeta(${MANIFEST_JSON@Q})
  }
}
print(json.dumps(manifest, indent=2))
PY

echo "OK: wrote ${MANIFEST_JSON}"
