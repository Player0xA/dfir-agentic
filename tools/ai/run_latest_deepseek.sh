#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   tools/ai/run_latest_deepseek.sh [RUN_ID|latest] [MODEL] [MAX_FINDINGS]
#
# Defaults:
#   RUN_ID=latest
#   MODEL=deepseek-chat
#   MAX_FINDINGS=30
#
# Requires:
#   - outputs/toon/chainsaw_evtx/<RUN_ID>/findings.toon
#   - tools/ai/deepseek_summarize_toon.py
#   - DEEPSEEK_API_KEY env var set

RUN_ID_ARG="${1:-latest}"
MODEL="${2:-deepseek-chat}"
MAX_FINDINGS="${3:-30}"

TOON_ROOT="outputs/toon/chainsaw_evtx"
AI_ROOT="outputs/ai/chainsaw_evtx"
SUMMARIZER="tools/ai/deepseek_summarize_toon.py"

fail() { echo "FAIL: $*" >&2; exit 2; }

test -f "$SUMMARIZER" || fail "missing summarizer: $SUMMARIZER"
test -d "$TOON_ROOT" || fail "missing TOON root dir: $TOON_ROOT"
test -n "${DEEPSEEK_API_KEY:-}" || fail "DEEPSEEK_API_KEY not set"

resolve_latest_run_id() {
  # 1) Prefer explicit pointer file
  if test -f "$TOON_ROOT/LATEST"; then
    cat "$TOON_ROOT/LATEST"
    return 0
  fi

  # 2) Fallback: newest directory under TOON_ROOT (excluding files)
  # Sort by mtime descending, pick first
  local latest
  latest="$(ls -1dt "$TOON_ROOT"/*/ 2>/dev/null | head -n 1 | xargs -r basename || true)"
  test -n "$latest" || return 1
  echo "$latest"
}

RUN_ID="$RUN_ID_ARG"
if [[ "$RUN_ID_ARG" == "latest" ]]; then
  RUN_ID="$(resolve_latest_run_id || true)"
  test -n "$RUN_ID" || fail "could not determine latest RUN_ID (no $TOON_ROOT/LATEST and no run dirs)"
fi

IN_TOON="$TOON_ROOT/$RUN_ID/findings.toon"
OUT_DIR="$AI_ROOT/$RUN_ID"
OUT_MD="$OUT_DIR/summary.md"

test -f "$IN_TOON" || fail "missing input TOON: $IN_TOON"
mkdir -p "$OUT_DIR"

echo "OK: using RUN_ID=$RUN_ID"
echo "OK: input toon=$IN_TOON"
echo "OK: output md=$OUT_MD"
echo

python3 "$SUMMARIZER" \
  --toon "$IN_TOON" \
  --model "$MODEL" \
  --max-findings "$MAX_FINDINGS" \
  --out "$OUT_MD"

echo
echo "Artifacts in: $OUT_DIR"
ls -lah "$OUT_DIR"

echo
echo "Preview: $OUT_MD"
sed -n '1,120p' "$OUT_MD"
