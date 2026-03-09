#!/usr/bin/env bash
set -euo pipefail

EVTX_DIR="${1:?EVTX_DIR required}"
CASE_ID="${2:-}"  # Optional case_id for findings aggregation
BASE_OUT_DIR="${3:-outputs/jsonl/chainsaw_evtx}"

CHAINSAW_BIN="/opt/dfir-tools/chainsaw/chainsaw.bin"
RULES_DIR="/opt/dfir-tools/chainsaw/rules/evtx"

FINDINGS_SCHEMA="contracts/findings.schema.json"
NORMALIZER="adapters/chainsaw_evtx_to_findings.py"
FINDINGS_VALIDATOR="tools/contracts/validate_findings.py"

MANIFEST_SCHEMA="contracts/manifest.schema.json"
MANIFEST_VALIDATOR="tools/contracts/validate_manifest.py"

TRIAGE_SCHEMA="contracts/triage.schema.json"
TRIAGE_GEN="tools/triage/gen_triage_from_findings.py"
TRIAGE_VALIDATOR="tools/contracts/validate_triage.py"

PIPELINE_NAME="chainsaw-evtx"
PIPELINE_VERSION="0.1.0"

# --- Preflight
test -x "$CHAINSAW_BIN" || { echo "FAIL: missing $CHAINSAW_BIN" >&2; exit 2; }
test -d "$RULES_DIR" || { echo "FAIL: missing $RULES_DIR" >&2; exit 2; }
test -d "$EVTX_DIR" || { echo "FAIL: EVTX_DIR not found: $EVTX_DIR" >&2; exit 2; }

test -f "$FINDINGS_SCHEMA" || { echo "FAIL: findings schema not found: $FINDINGS_SCHEMA" >&2; exit 2; }
test -f "$NORMALIZER" || { echo "FAIL: normalizer not found: $NORMALIZER" >&2; exit 2; }
test -x "$FINDINGS_VALIDATOR" || { echo "FAIL: findings validator not executable: $FINDINGS_VALIDATOR" >&2; exit 2; }

test -f "$MANIFEST_SCHEMA" || { echo "FAIL: manifest schema not found: $MANIFEST_SCHEMA" >&2; exit 2; }
test -x "$MANIFEST_VALIDATOR" || { echo "FAIL: manifest validator not executable: $MANIFEST_VALIDATOR" >&2; exit 2; }

test -f "$TRIAGE_SCHEMA" || { echo "FAIL: triage schema not found: $TRIAGE_SCHEMA" >&2; exit 2; }
test -x "$TRIAGE_GEN" || { echo "FAIL: triage generator not executable: $TRIAGE_GEN" >&2; exit 2; }
test -x "$TRIAGE_VALIDATOR" || { echo "FAIL: triage validator not executable: $TRIAGE_VALIDATOR" >&2; exit 2; }

# --- Run identity
RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
TS_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export RUN_ID TS_UTC PIPELINE_NAME PIPELINE_VERSION

# --- Per-run output directory
OUT_DIR="$BASE_OUT_DIR/$RUN_ID"
mkdir -p "$OUT_DIR"

CHAINSAW_OUT="$OUT_DIR/chainsaw.evtx.jsonl"
FINDINGS_OUT="$OUT_DIR/findings.json"
TRIAGE_OUT="$OUT_DIR/triage.json"

REQUEST_JSON="$OUT_DIR/request.json"
ERROR_JSON="$OUT_DIR/error.json"
MANIFEST_JSON="$OUT_DIR/manifest.json"
STDOUT_LOG="$OUT_DIR/stdout.log"
STDERR_LOG="$OUT_DIR/stderr.log"

exec 1> >(tee -a "$STDOUT_LOG")
exec 2> >(tee -a "$STDERR_LOG" >&2)

fail() {
  local code="${1:-1}"
  local msg="${2:-pipeline failed}"
  python3 - <<PY > "$ERROR_JSON" || true
import json, os
out = {
  "run_id": os.environ.get("RUN_ID"),
  "timestamp_utc": os.environ.get("TS_UTC"),
  "pipeline": {"name": os.environ.get("PIPELINE_NAME"), "version": os.environ.get("PIPELINE_VERSION")},
  "status": "error",
  "exit_code": int(os.environ.get("PIPELINE_EXIT_CODE", "${code}")),
  "message": ${msg@Q},
}
print(json.dumps(out, indent=2))
PY
  echo "FAIL: $msg" >&2
  exit "$code"
}
trap 'export PIPELINE_EXIT_CODE="$?"; fail "$PIPELINE_EXIT_CODE" "unexpected error (see stderr.log)"' ERR

CHAINSAW_VERSION="$("$CHAINSAW_BIN" --version | awk '{print $2}')"
test -n "$CHAINSAW_VERSION" || fail 3 "could not determine chainsaw version"

python3 - <<PY > "$REQUEST_JSON"
import json, os
req = {
  "run_id": os.environ["RUN_ID"],
  "timestamp_utc": os.environ["TS_UTC"],
  "pipeline": {"name": os.environ["PIPELINE_NAME"], "version": os.environ["PIPELINE_VERSION"]},
  "case_id": ${CASE_ID@Q},
  "inputs": {"evtx_dir": ${EVTX_DIR@Q}},
  "tools": {
    "chainsaw_bin": ${CHAINSAW_BIN@Q},
    "chainsaw_version": ${CHAINSAW_VERSION@Q},
    "rules_dir": ${RULES_DIR@Q},
    "normalizer": ${NORMALIZER@Q},
    "findings_schema": ${FINDINGS_SCHEMA@Q},
    "findings_validator": ${FINDINGS_VALIDATOR@Q},
    "triage_schema": ${TRIAGE_SCHEMA@Q},
    "triage_generator": ${TRIAGE_GEN@Q},
    "triage_validator": ${TRIAGE_VALIDATOR@Q},
    "manifest_schema": ${MANIFEST_SCHEMA@Q},
    "manifest_validator": ${MANIFEST_VALIDATOR@Q},
    "toon_cli": "@toon-format/cli"
  }
}
print(json.dumps(req, indent=2))
PY

echo "INFO: starting pipeline"
echo "  RUN_ID: $RUN_ID"
echo "  TS_UTC: $TS_UTC"
echo "  EVTX_DIR: $EVTX_DIR"
echo "  OUT_DIR: $OUT_DIR"
echo "  CHAINSAW_VERSION: $CHAINSAW_VERSION"

"$CHAINSAW_BIN" hunt "$RULES_DIR" "$EVTX_DIR" --jsonl -o "$CHAINSAW_OUT" --skip-errors
test -s "$CHAINSAW_OUT" || fail 4 "chainsaw produced empty jsonl: $CHAINSAW_OUT"

python3 "$NORMALIZER" \
  --run-id "$RUN_ID" \
  --timestamp-utc "$TS_UTC" \
  --pipeline-name "$PIPELINE_NAME" \
  --pipeline-version "$PIPELINE_VERSION" \
  --chainsaw-version "$CHAINSAW_VERSION" \
  --input-jsonl "$CHAINSAW_OUT" \
  --output-json "$FINDINGS_OUT"

test -s "$FINDINGS_OUT" || fail 4 "normalizer produced empty findings: $FINDINGS_OUT"

"$FINDINGS_VALIDATOR" "$FINDINGS_SCHEMA" "$FINDINGS_OUT"

# --- Deterministic triage (router-grade, non-AI)
"$TRIAGE_GEN" \
  --run-id "$RUN_ID" \
  --timestamp-utc "$TS_UTC" \
  --pipeline-name "$PIPELINE_NAME" \
  --pipeline-version "$PIPELINE_VERSION" \
  --findings-json "$FINDINGS_OUT" \
  --output-json "$TRIAGE_OUT" \
  --top-n 25

test -s "$TRIAGE_OUT" || fail 4 "triage produced empty triage.json: $TRIAGE_OUT"
"$TRIAGE_VALIDATOR" "$TRIAGE_SCHEMA" "$TRIAGE_OUT"

OUT_TOON_DIR="outputs/toon/chainsaw_evtx/$RUN_ID"
mkdir -p "$OUT_TOON_DIR"
FINDINGS_TOON="$OUT_TOON_DIR/findings.toon"

npx --yes @toon-format/cli --encode -o "$FINDINGS_TOON" "$FINDINGS_OUT"
test -s "$FINDINGS_TOON" || fail 5 "findings.toon empty: $FINDINGS_TOON"

printf "%s\n" "$RUN_ID" > outputs/toon/chainsaw_evtx/LATEST
printf "%s\n" "$RUN_ID" > outputs/jsonl/chainsaw_evtx/LATEST

python3 - <<PY > "$MANIFEST_JSON"
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

run_id = os.environ["RUN_ID"]
ts_utc = os.environ["TS_UTC"]

evtx_dir = ${EVTX_DIR@Q}
chainsaw_bin = ${CHAINSAW_BIN@Q}
rules_dir = ${RULES_DIR@Q}
chainsaw_ver = ${CHAINSAW_VERSION@Q}

chainsaw_out = ${CHAINSAW_OUT@Q}
findings_out = ${FINDINGS_OUT@Q}
triage_out = ${TRIAGE_OUT@Q}
request_json = ${REQUEST_JSON@Q}
stdout_log = ${STDOUT_LOG@Q}
stderr_log = ${STDERR_LOG@Q}
findings_toon = ${FINDINGS_TOON@Q}

manifest = {
  "run_id": run_id,
  "timestamp_utc": ts_utc,
  "pipeline": {"name": os.environ["PIPELINE_NAME"], "version": os.environ["PIPELINE_VERSION"]},
  "status": "ok",
  "inputs": {
    "evtx_dir": evtx_dir,
    "evtx_files": list_evtx(evtx_dir),
  },
  "tooling": {
    "chainsaw": {
      "path": chainsaw_bin,
      "version": chainsaw_ver,
      "rules_dir": rules_dir,
      "cmd": [chainsaw_bin, "hunt", rules_dir, evtx_dir, "--jsonl", "-o", chainsaw_out],
    },
    "normalizer": {"path": ${NORMALIZER@Q}},
    "schema": {"path": ${FINDINGS_SCHEMA@Q}},
    "validator": {"path": ${FINDINGS_VALIDATOR@Q}},
    "triage": {"generator": ${TRIAGE_GEN@Q}},
    "toon": {"cli": "@toon-format/cli"},
  },
  "artifacts": {
    "request": fmeta(request_json),
    "chainsaw_jsonl": fmeta(chainsaw_out),
    "findings_json": fmeta(findings_out),
    "triage_json": fmeta(triage_out),
    "findings_toon": fmeta(findings_toon),
    "stdout_log": fmeta(stdout_log),
    "stderr_log": fmeta(stderr_log),
  },
  "latest": {
    "outputs/toon/chainsaw_evtx/LATEST": True,
    "outputs/jsonl/chainsaw_evtx/LATEST": True,
  }
}
print(json.dumps(manifest, indent=2))
PY

"$MANIFEST_VALIDATOR" "$MANIFEST_SCHEMA" "$MANIFEST_JSON"

echo "OK: pipeline complete"
echo "  RUN_ID:        $RUN_ID"
echo "  chainsaw_out:  $CHAINSAW_OUT"
echo "  findings_out:  $FINDINGS_OUT"
echo "  triage_out:    $TRIAGE_OUT"
echo "  toon_out:      $FINDINGS_TOON"
echo "  request:       $REQUEST_JSON"
echo "  manifest:      $MANIFEST_JSON"

