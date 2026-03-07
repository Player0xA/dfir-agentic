#!/bin/bash
set -e

# Plaso Pipeline Runner for dfir-agentic
# Generates a .plaso super timeline from an EVTX directory.

RUN_ID="${1}"
TS_UTC="${2}"
EVIDENCE_DIR="${3}"
# Expand tilde if present
if [[ "${EVIDENCE_DIR}" == "~"* ]]; then
  EVIDENCE_DIR="${EVIDENCE_DIR/#\~/$HOME}"
fi
OUT_ROOT="${4:-outputs/plaso_evtx}"

L2T_BIN="${L2T_BIN:-log2timeline.py}"
PLASO_DIR="${OUT_ROOT}/${RUN_ID}"
PLASO_FILE="${PLASO_DIR}/case.plaso"
REQUEST_JSON="${PLASO_DIR}/request.json"
MANIFEST_JSON="${PLASO_DIR}/manifest.json"

mkdir -p "${PLASO_DIR}"

echo "INFO: Generating Plaso timeline"
echo "  RUN_ID:       ${RUN_ID}"
echo "  EVIDENCE_DIR: ${EVIDENCE_DIR}"
echo "  OUT_FILE:     ${PLASO_FILE}"

# 1. Audit Request
cat <<EOF > "${REQUEST_JSON}"
{
  "timestamp_utc": "${TS_UTC}",
  "pipeline": "plaso_evtx",
  "run_id": "${RUN_ID}",
  "evidence_dir": "${EVIDENCE_DIR}",
  "plaso": {
    "bin": "${L2T_BIN}",
    "storage_file": "${PLASO_FILE}"
  }
}
EOF

# 2. Run log2timeline with explicit Windows parser list (Tiers 1-8)
LOG_FILE="${PLASO_DIR}/plaso.log"

# Tier 1: Core Windows Timeline Artifacts
T1="winevtx,winevt,winreg,prefetch,mft,usnjrnl"

# Tier 2: High Value Activity Artifacts
T2="lnk,olecf/olecf_automatic_destinations,custom_destinations,winjob,recycle_bin,recycle_bin_info2,winpca_db0,winpca_dic"

# Tier 3: Browser and Web Activity
T3="sqlite/chrome_8_history,sqlite/chrome_17_cookies,sqlite/chrome_27_history,sqlite/chrome_66_cookies,sqlite/chrome_autofill,sqlite/chrome_extension_activity"
T3="${T3},sqlite/firefox_history,sqlite/firefox_2_cookies,sqlite/firefox_10_cookies,sqlite/firefox_downloads,firefox_cache,firefox_cache2"
T3="${T3},msiecf,esedb/msie_webcache,opera_global,opera_typed_history"

# Tier 4: System Usage Databases
T4="esedb/srum,sqlite/windows_timeline,sqlite/windows_eventtranscript,esedb/file_history,esedb/user_access_logging"

# Tier 5: System / Security Logs
T5="text/winfirewall,text/setupapi,text/winiis"

# Tier 6: Security / AV Logs
T6="windefender_history,symantec_scanlog,mcafee_protection,trendmicro_url,trendmicro_vd,text/sophos_av"

# Tier 7: Cloud / Sync / External Activity
T7="onedrive_log,text/skydrive_log_v1,text/skydrive_log_v2,text/gdrive_synclog,sqlite/google_drive"

# Tier 8: Miscellaneous Windows Artifacts
T8="pe,networkminer_fileinfo"

WINDOWS_PARSERS="${T1},${T2},${T3},${T4},${T5},${T6},${T7},${T8}"

echo "INFO: Using explicit Windows parser list (Tiers 1-8)"
"${L2T_BIN}" -q -u --status_view none --parsers "${WINDOWS_PARSERS}" --logfile "${LOG_FILE}" --storage_file "${PLASO_FILE}" "${EVIDENCE_DIR}"

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
    "evidence_dir": ${EVIDENCE_DIR@Q}
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
