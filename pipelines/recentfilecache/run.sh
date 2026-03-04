#!/bin/bash
set -e

# RecentFileCacheParser Pipeline Runner for dfir-agentic
# Generates a CSV from Windows Application Compatibility cache (RecentFileCache.bcf)

RUN_ID="${1}"
TS_UTC="${2}"
TARGET_PATH="${3}"

if [[ "${TARGET_PATH}" == "~"* ]]; then
  TARGET_PATH="${TARGET_PATH/#\~/$HOME}"
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_CSV_DIR="${PROJECT_ROOT}/outputs/csv/recentfilecache/${RUN_ID}"
OUT_JSON_DIR="${PROJECT_ROOT}/outputs/jsonl/recentfilecache/${RUN_ID}"

mkdir -p "${OUT_CSV_DIR}" "${OUT_JSON_DIR}"

# Find RFC executable
RFC_BIN=$(which recentfilecacheparser || which RecentFileCacheParser || which RecentFileCacheParser.exe || echo "RecentFileCacheParser")

REQUEST_JSON="${OUT_JSON_DIR}/request.json"
MANIFEST_JSON="${OUT_JSON_DIR}/manifest.json"
STDOUT_LOG="${OUT_JSON_DIR}/stdout.log"
STDERR_LOG="${OUT_JSON_DIR}/stderr.log"

echo "INFO: Generating RecentFileCacheParser CSV"
echo "  RUN_ID:   ${RUN_ID}"
echo "  TARGET:   ${TARGET_PATH}"
echo "  OUT_DIR:  ${OUT_CSV_DIR}"

if [[ ! -f "${TARGET_PATH}" ]]; then
  echo "FAIL: Target file not found at ${TARGET_PATH}" >&2
  exit 1
fi

# 1. Audit Request
cat <<EOF > "${REQUEST_JSON}"
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "recentfilecache",
  "run_id": "${RUN_ID}",
  "target_path": "${TARGET_PATH}",
  "tool": {
    "bin": "${RFC_BIN}",
    "out_dir": "${OUT_CSV_DIR}"
  }
}
EOF

# 2. Run RecentFileCacheParser
# Note: Zimmerman tools output files formatted as: <timestamp>_RecentFileCacheParser_Output.csv
set +e
"${RFC_BIN}" -f "${TARGET_PATH}" --csv "${OUT_CSV_DIR}" >"${STDOUT_LOG}" 2>"${STDERR_LOG}"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "FAIL: RecentFileCacheParser failed (rc=${RC})" >&2
  echo "  stderr: ${STDERR_LOG}" >&2
  exit 2
fi

# Find the generated CSV (Zimmerman tools prepend datetimes)
GENERATED_CSV=$(find "${OUT_CSV_DIR}" -name "*RecentFileCacheParser_Output.csv" | head -n 1)

if [[ -z "${GENERATED_CSV}" ]]; then
  GENERATED_CSV=$(find "${OUT_CSV_DIR}" -name "*RecentFileCacheParser*.csv" | head -n 1)
fi

if [[ -z "${GENERATED_CSV}" ]]; then
  echo "FAIL: No CSV output found in ${OUT_CSV_DIR} after running tool" >&2
  exit 2
fi

FINDINGS_JSON="${OUT_JSON_DIR}/findings.json"
ADAPTER_CONTRACT="${PROJECT_ROOT}/adapters/recentfilecache_csv_to_findings_contract.py"

python3 -u "${ADAPTER_CONTRACT}" \
  --input-csv "${GENERATED_CSV}" \
  --out-json "${FINDINGS_JSON}" \
  --run-id "${RUN_ID}" \
  --timestamp-utc "${TS_UTC}" \
  --target-path "${TARGET_PATH}"

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
  "pipeline": {"name": "recentfilecache", "version": "0.1.0"},
  "status": "ok",
  "inputs": {
    "target_path": ${TARGET_PATH@Q}
  },
  "tooling": {
    "recentfilecacheparser": {
      "path": ${RFC_BIN@Q}
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
    "outputs/jsonl/recentfilecache/LATEST": True,
  }
}
print(json.dumps(manifest, indent=2))
PY

LATEST_FILE="${PROJECT_ROOT}/outputs/jsonl/recentfilecache/LATEST"
mkdir -p "${PROJECT_ROOT}/outputs/jsonl/recentfilecache"
echo "${RUN_ID}" > "${LATEST_FILE}"

echo "OK: wrote ${MANIFEST_JSON}"
exit 0
