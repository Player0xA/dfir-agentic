#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   pipelines/hayabusa_evtx/run.sh /path/to/evtx_dir
#
# Outputs:
#   outputs/csv/hayabusa_evtx/<run_id>/timeline.csv
#   outputs/jsonl/hayabusa_evtx/<run_id>/findings.json
#   outputs/jsonl/hayabusa_evtx/<run_id>/{stdout.log,stderr.log,request.json}

EVTX_DIR="${1:-}"
TIER="quick"
if [[ "${2:-}" == "--tier" && -n "${3:-}" ]]; then
  TIER="${3}"
fi

case "${TIER}" in
  quick)
    HAYA_TIER_ARGS=( -P -E -m medium )
    ;;
  deep)
    HAYA_TIER_ARGS=( -A -m informational -s )
    ;;
  *)
    echo "FAIL: invalid tier: ${TIER} (expected: quick|deep)" >&2
    exit 2
    ;;
esac


if [[ -z "${EVTX_DIR}" ]]; then
  echo "FAIL: missing EVTX_DIR argument" >&2
  echo "Usage: $0 /path/to/evtx_dir" >&2
  exit 2
fi

if [[ ! -d "${EVTX_DIR}" ]]; then
  echo "FAIL: EVTX_DIR is not a directory: ${EVTX_DIR}" >&2
  exit 2
fi

TMP_LATEST=""
cleanup() { [[ -n "${TMP_LATEST}" && -f "${TMP_LATEST}" ]] && rm -f "${TMP_LATEST}"; return 0; }
trap cleanup EXIT


PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAYA_ROOT="${PROJECT_ROOT}/tools/hayabusa"
HAYA_BIN="${HAYA_ROOT}/bin/hayabusa"
RULES_DIR="${HAYA_ROOT}/rules"
CONFIG_DIR="${HAYA_ROOT}/rules/config"

ADAPTER_CONTRACT="${PROJECT_ROOT}/adapters/hayabusa_csv_to_findings_contract.py"

FINDINGS_SCHEMA="${PROJECT_ROOT}/contracts/findings.schema.json"
FINDINGS_VALIDATOR="${PROJECT_ROOT}/tools/contracts/validate_findings.py"

MANIFEST_SCHEMA="${PROJECT_ROOT}/contracts/manifest.hayabusa.schema.json"
MANIFEST_VALIDATOR="${PROJECT_ROOT}/tools/contracts/validate_manifest.py"

PIPELINE_NAME="hayabusa-evtx"
PIPELINE_VERSION="0.1.0"

# Deterministic-ish run id (uuid4)
RUN_ID="$(python3 - <<'PY'
import uuid
print(str(uuid.uuid4()))
PY
)"

# Validate RUN_ID shape (UUID)
if ! [[ "$RUN_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "FAIL: RUN_ID not UUID hex: $RUN_ID" >&2
  exit 2
fi


TS_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

HAYA_VERSION="$(
  set +e
  line="$("${HAYA_BIN}" help 2>/dev/null | head -n 1)"
  rc=$?
  if [[ $rc -ne 0 || -z "$line" ]]; then
    echo "unknown"
    exit 0
  fi
  ver="$(echo "$line" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
  if [[ -n "$ver" ]]; then
    echo "$ver"
  else
    echo "unknown"
  fi
)"

OUT_CSV_DIR="${PROJECT_ROOT}/outputs/csv/hayabusa_evtx/${RUN_ID}"
OUT_JSON_DIR="${PROJECT_ROOT}/outputs/jsonl/hayabusa_evtx/${RUN_ID}"
TIMELINE_CSV="${OUT_CSV_DIR}/timeline.csv"
FINDINGS_JSON="${OUT_JSON_DIR}/findings.json"
STDOUT_LOG="${OUT_JSON_DIR}/stdout.log"
STDERR_LOG="${OUT_JSON_DIR}/stderr.log"
REQUEST_JSON="${OUT_JSON_DIR}/request.json"
OUT_JSON_ROOT="${PROJECT_ROOT}/outputs/jsonl/hayabusa_evtx"
MANIFEST_JSON="${OUT_JSON_DIR}/manifest.json"



mkdir -p "${OUT_CSV_DIR}" "${OUT_JSON_DIR}"

# Basic sanity checks (fail fast)
test -x "${HAYA_BIN}" || { echo "FAIL: hayabusa binary not executable: ${HAYA_BIN}" >&2; exit 2; }
test -d "${RULES_DIR}" || { echo "FAIL: rules dir missing: ${RULES_DIR}" >&2; exit 2; }
test -d "${CONFIG_DIR}" || { echo "FAIL: config dir missing: ${CONFIG_DIR}" >&2; exit 2; }
test -f "${ADAPTER_CONTRACT}" || { echo "FAIL: contract adapter not found: ${ADAPTER_CONTRACT}" >&2; exit 2; }

test -f "${FINDINGS_SCHEMA}" || { echo "FAIL: findings schema not found: ${FINDINGS_SCHEMA}" >&2; exit 2; }
test -x "${FINDINGS_VALIDATOR}" || { echo "FAIL: findings validator not executable: ${FINDINGS_VALIDATOR}" >&2; exit 2; }

test -f "${MANIFEST_SCHEMA}" || { echo "FAIL: hayabusa manifest schema not found: ${MANIFEST_SCHEMA}" >&2; exit 2; }
test -x "${MANIFEST_VALIDATOR}" || { echo "FAIL: manifest validator not executable: ${MANIFEST_VALIDATOR}" >&2; exit 2; }


# Required config files (avoids the noisy [ERROR] on future automation)
for f in \
  "${CONFIG_DIR}/channel_abbreviations.txt" \
  "${CONFIG_DIR}/provider_abbreviations.txt" \
  "${CONFIG_DIR}/default_details.txt" \
  "${CONFIG_DIR}/channel_eid_info.txt" \
  "${CONFIG_DIR}/target_event_IDs.txt"
do
  test -s "${f}" || { echo "FAIL: missing/empty ${f}" >&2; exit 2; }
done

# Record the deterministic request envelope
cat > "${REQUEST_JSON}" <<JSON
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "hayabusa_evtx",
  "run_id": "${RUN_ID}",
  "evtx_dir": "${EVTX_DIR}",
  "hayabusa": {
    "bin": "${HAYA_BIN}",
    "rules_dir": "${RULES_DIR}",
    "config_dir": "${CONFIG_DIR}",
    "profile": "verbose",
    "iso_utc": true,
    "no_wizard": true,
    "clobber": true
  },
  "outputs": {
    "timeline_csv": "${TIMELINE_CSV}",
    "findings_json": "${FINDINGS_JSON}",
    "manifest_json": "${MANIFEST_JSON}"
  }
}
JSON

echo "INFO: starting hayabusa pipeline"
echo "  RUN_ID:   ${RUN_ID}"
echo "  TS_UTC:   ${TS_UTC}"
echo "  EVTX_DIR: ${EVTX_DIR}"
echo "  OUT_CSV:  ${OUT_CSV_DIR}"
echo "  OUT_JSON: ${OUT_JSON_DIR}"

# 1) Run Hayabusa (absolute paths; no CWD dependence)
set +e
"${HAYA_BIN}" csv-timeline \
  -d "${EVTX_DIR}" \
  -w \
  -r "${RULES_DIR}" \
  -c "${CONFIG_DIR}" \
  -p verbose \
  -O \
  -C \
  -o "${TIMELINE_CSV}" \
  >"${STDOUT_LOG}" 2>"${STDERR_LOG}"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "FAIL: hayabusa csv-timeline failed (rc=${RC})" >&2
  echo "  stderr: ${STDERR_LOG}" >&2
  exit 2
fi

test -s "${TIMELINE_CSV}" || { echo "FAIL: timeline.csv not created or empty: ${TIMELINE_CSV}" >&2; exit 2; }

# 2) Adapt CSV -> findings.json
# 2) Adapt CSV -> findings.json (CONTRACT SHAPE)
python3 -u "${ADAPTER_CONTRACT}" \
  --input-csv "${TIMELINE_CSV}" \
  --out-json "${FINDINGS_JSON}" \
  --run-id "${RUN_ID}" \
  --timestamp-utc "${TS_UTC}" \
  --pipeline-name "${PIPELINE_NAME}" \
  --pipeline-version "${PIPELINE_VERSION}" \
  --hayabusa-version "${HAYA_VERSION}" \
  --evtx-dir "${EVTX_DIR}" \
  --profile "verbose"


test -s "${FINDINGS_JSON}" || { echo "FAIL: findings.json not created or empty: ${FINDINGS_JSON}" >&2; exit 2; }
"${FINDINGS_VALIDATOR}" "${FINDINGS_SCHEMA}" "${FINDINGS_JSON}"

# Optional hard gate if/when your schema matches the adapter output:
# python3 -u tools/contracts/validate_findings.py contracts/findings.schema.json "${FINDINGS_JSON}"


# --- update LATEST pointer (atomic) ---
LATEST_FILE="${OUT_JSON_ROOT}/LATEST"
TMP_LATEST="$(mktemp)"
printf '%s\n' "$RUN_ID" > "$TMP_LATEST"
mv -f "$TMP_LATEST" "$LATEST_FILE"
# -------------------------------------
python3 - <<PY > "${MANIFEST_JSON}"
import os, json, hashlib, pathlib

def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fmeta(p: str):
    st = os.stat(p)
    return {"path": p, "sha256": sha256(p), "size": st.st_size}

def list_evtx(evtx_dir: str):
    paths = sorted(str(p) for p in pathlib.Path(evtx_dir).rglob("*.evtx"))
    out = []
    for p in paths:
        st = os.stat(p)
        out.append({"path": p, "sha256": sha256(p), "size": st.st_size})
    return out

manifest = {
  "run_id": ${RUN_ID@Q},
  "timestamp_utc": ${TS_UTC@Q},
  "pipeline": {"name": ${PIPELINE_NAME@Q}, "version": ${PIPELINE_VERSION@Q}},
  "status": "ok",
  "inputs": {
    "evtx_dir": ${EVTX_DIR@Q},
    "evtx_files": list_evtx(${EVTX_DIR@Q}),
  },
  "tooling": {
    "hayabusa": {
      "path": ${HAYA_BIN@Q},
      "version": ${HAYA_VERSION@Q},
      "rules_dir": ${RULES_DIR@Q},
      "config_dir": ${CONFIG_DIR@Q},
      "profile": "verbose",
      "cmd": [
        ${HAYA_BIN@Q}, "csv-timeline",
        "-d", ${EVTX_DIR@Q},
        "-w",
        "-r", ${RULES_DIR@Q},
        "-c", ${CONFIG_DIR@Q},
        "-p", "verbose",
        "-O",
        "-C",
        "-o", ${TIMELINE_CSV@Q}
      ],
    },
    "normalizer": {"path": ${ADAPTER_CONTRACT@Q}},
    "schema": {"path": ${FINDINGS_SCHEMA@Q}},
    "validator": {"path": ${FINDINGS_VALIDATOR@Q}},
  },
  "artifacts": {
    "request": fmeta(${REQUEST_JSON@Q}),
    "timeline_csv": fmeta(${TIMELINE_CSV@Q}),
    "findings_json": fmeta(${FINDINGS_JSON@Q}),
    "stdout_log": fmeta(${STDOUT_LOG@Q}),
    "stderr_log": fmeta(${STDERR_LOG@Q}),
    "manifest_json": fmeta(${MANIFEST_JSON@Q}),
  },
  "latest": {
    "outputs/jsonl/hayabusa_evtx/LATEST": True,
  }
}
print(json.dumps(manifest, indent=2))
PY

"${MANIFEST_VALIDATOR}" "${MANIFEST_SCHEMA}" "${MANIFEST_JSON}"


echo "OK: pipeline complete"
echo "  RUN_ID:       ${RUN_ID}"
echo "  timeline_csv: ${TIMELINE_CSV}"
echo "  findings_json:${FINDINGS_JSON}"
echo "OK: wrote ${OUT_JSON_DIR}/request.json"
echo "  manifest_json:${MANIFEST_JSON}"

