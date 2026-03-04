#!/bin/bash
set -e

# AppCompatCacheParser Pipeline Runner for dfir-agentic
# Generates a CSV from a SYSTEM registry hive using Zimmerman's tool.

RUN_ID="${1}"
TS_UTC="${2}"
SYSTEM_HIVE="${3}"
# Expand tilde if present
if [[ "${SYSTEM_HIVE}" == "~"* ]]; then
  SYSTEM_HIVE="${SYSTEM_HIVE/#\~/$HOME}"
fi

# The global output directories used by the dashboard server parser
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_CSV_DIR="${PROJECT_ROOT}/outputs/csv/appcompatcache/${RUN_ID}"
OUT_JSON_DIR="${PROJECT_ROOT}/outputs/jsonl/appcompatcache/${RUN_ID}"

mkdir -p "${OUT_CSV_DIR}" "${OUT_JSON_DIR}"

ACP_BIN="/usr/local/bin/appcompatcacheparser"
REQUEST_JSON="${OUT_JSON_DIR}/request.json"
MANIFEST_JSON="${OUT_JSON_DIR}/manifest.json"
STDOUT_LOG="${OUT_JSON_DIR}/stdout.log"
STDERR_LOG="${OUT_JSON_DIR}/stderr.log"

echo "INFO: Generating AppCompatCache CSV"
echo "  RUN_ID:   ${RUN_ID}"
echo "  HIVE:     ${SYSTEM_HIVE}"
echo "  OUT_DIR:  ${OUT_CSV_DIR}"

if [[ ! -f "${SYSTEM_HIVE}" ]]; then
  echo "FAIL: SYSTEM hive file not found at ${SYSTEM_HIVE}" >&2
  exit 1
fi

if [[ ! -x "${ACP_BIN}" ]]; then
  echo "FAIL: AppCompatCacheParser not found or not executable at ${ACP_BIN}" >&2
  exit 1
fi

# 1. Audit Request
cat <<EOF > "${REQUEST_JSON}"
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "appcompatcache",
  "run_id": "${RUN_ID}",
  "system_hive": "${SYSTEM_HIVE}",
  "tool": {
    "bin": "${ACP_BIN}",
    "out_dir": "${OUT_CSV_DIR}"
  }
}
EOF

# 2. Run AppCompatCacheParser
# Note: Zimmerman tools output files formatted as: <timestamp>_AppCompatCache.csv
# We direct the output directory to OUT_CSV_DIR
set +e
"${ACP_BIN}" -f "${SYSTEM_HIVE}" --csv "${OUT_CSV_DIR}" >"${STDOUT_LOG}" 2>"${STDERR_LOG}"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "FAIL: AppCompatCacheParser failed (rc=${RC})" >&2
  echo "  stderr: ${STDERR_LOG}" >&2
  exit 2
fi

# Find the generated CSV (Zimmerman tools prepend datetimes)
GENERATED_CSV=$(find "${OUT_CSV_DIR}" -name "*AppCompatCache.csv" | head -n 1)

if [[ -z "${GENERATED_CSV}" ]]; then
  echo "FAIL: No CSV output found in ${OUT_CSV_DIR} after running tool" >&2
  exit 2
fi

FINDINGS_JSON="${OUT_JSON_DIR}/findings.json"
ADAPTER_CONTRACT="${PROJECT_ROOT}/adapters/appcompatcache_csv_to_findings_contract.py"

python3 -u "${ADAPTER_CONTRACT}" \
  --input-csv "${GENERATED_CSV}" \
  --out-json "${FINDINGS_JSON}" \
  --run-id "${RUN_ID}" \
  --timestamp-utc "${TS_UTC}" \
  --system-hive "${SYSTEM_HIVE}"

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
  "pipeline": {"name": "appcompatcache", "version": "0.1.0"},
  "status": "ok",
  "inputs": {
    "system_hive": ${SYSTEM_HIVE@Q}
  },
  "tooling": {
    "appcompatcacheparser": {
      "path": ${ACP_BIN@Q}
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
    "outputs/jsonl/appcompatcache/LATEST": True,
  }
}
print(json.dumps(manifest, indent=2))
PY

LATEST_FILE="${PROJECT_ROOT}/outputs/jsonl/appcompatcache/LATEST"
mkdir -p "${PROJECT_ROOT}/outputs/jsonl/appcompatcache"
echo "${RUN_ID}" > "${LATEST_FILE}"

echo "OK: wrote ${MANIFEST_JSON}"
exit 0
