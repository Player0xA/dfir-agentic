#!/bin/bash
set -e

# MFTECmd Pipeline Runner for dfir-agentic
# Generates a CSV from a master file table file using Zimmerman's tool.

RUN_ID="${1}"
TS_UTC="${2}"
MFT_FILE="${3}"
# Expand tilde if present
if [[ "${MFT_FILE}" == "~"* ]]; then
  MFT_FILE="${MFT_FILE/#\~/$HOME}"
fi

# The global output directories used by the dashboard server parser
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_CSV_DIR="${PROJECT_ROOT}/outputs/csv/mftecmd/${RUN_ID}"
OUT_JSON_DIR="${PROJECT_ROOT}/outputs/jsonl/mftecmd/${RUN_ID}"

mkdir -p "${OUT_CSV_DIR}" "${OUT_JSON_DIR}"

# Just call MFTECmd assumed to be in PATH, or you can specify full path
MFT_BIN=$(which MFTECmd || which MFTECmd.exe || echo "MFTECmd")

REQUEST_JSON="${OUT_JSON_DIR}/request.json"
MANIFEST_JSON="${OUT_JSON_DIR}/manifest.json"
STDOUT_LOG="${OUT_JSON_DIR}/stdout.log"
STDERR_LOG="${OUT_JSON_DIR}/stderr.log"

echo "INFO: Generating MFTECmd CSV"
echo "  RUN_ID:   ${RUN_ID}"
echo "  MFT:      ${MFT_FILE}"
echo "  OUT_DIR:  ${OUT_CSV_DIR}"

if [[ ! -f "${MFT_FILE}" ]]; then
  echo "FAIL: MFT file not found at ${MFT_FILE}" >&2
  exit 1
fi

# 1. Audit Request
cat <<EOF > "${REQUEST_JSON}"
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "mftecmd",
  "run_id": "${RUN_ID}",
  "mft_file": "${MFT_FILE}",
  "tool": {
    "bin": "${MFT_BIN}",
    "out_dir": "${OUT_CSV_DIR}"
  }
}
EOF

# 2. Run MFTECmd
# Note: Zimmerman tools output files formatted as: <timestamp>_MFTECmd.csv
set +e
"${MFT_BIN}" -f "${MFT_FILE}" --csv "${OUT_CSV_DIR}" >"${STDOUT_LOG}" 2>"${STDERR_LOG}"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "FAIL: MFTECmd failed (rc=${RC})" >&2
  echo "  stderr: ${STDERR_LOG}" >&2
  exit 2
fi

# Find the generated CSV (Zimmerman tools prepend datetimes)
GENERATED_CSV=$(find "${OUT_CSV_DIR}" -name "*MFTECmd.csv" | head -n 1)

if [[ -z "${GENERATED_CSV}" ]]; then
  echo "FAIL: No CSV output found in ${OUT_CSV_DIR} after running tool" >&2
  exit 2
fi

FINDINGS_JSON="${OUT_JSON_DIR}/findings.json"
ADAPTER_CONTRACT="${PROJECT_ROOT}/adapters/mftecmd_csv_to_findings_contract.py"

python3 -u "${ADAPTER_CONTRACT}" \
  --input-csv "${GENERATED_CSV}" \
  --out-json "${FINDINGS_JSON}" \
  --run-id "${RUN_ID}" \
  --timestamp-utc "${TS_UTC}" \
  --mft-file "${MFT_FILE}"

# 3. Generate Manifest
python3 - <<PY > "${MANIFEST_JSON}"
import os, json, hashlib

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
  "pipeline": {"name": "mftecmd", "version": "0.1.0"},
  "status": "ok",
  "inputs": {
    "mft_file": ${MFT_FILE@Q}
  },
  "tooling": {
    "mftecmd": {
      "path": ${MFT_BIN@Q}
    },
    "normalizer": {"path": ${ADAPTER_CONTRACT@Q}}
  },
  "artifacts": {
    "request_json": fmeta(${REQUEST_JSON@Q}),
    "timeline_csv": fmeta(${GENERATED_CSV@Q}),
    "findings_json": fmeta(${FINDINGS_JSON@Q}),
    "manifest_json": fmeta(${MANIFEST_JSON@Q})
  },
  "latest": {
    "outputs/jsonl/mftecmd/LATEST": True,
  }
}
print(json.dumps(manifest, indent=2))
PY

LATEST_FILE="${PROJECT_ROOT}/outputs/jsonl/mftecmd/LATEST"
mkdir -p "${PROJECT_ROOT}/outputs/jsonl/mftecmd"
echo "${RUN_ID}" > "${LATEST_FILE}"

echo "OK: wrote ${MANIFEST_JSON}"
exit 0
