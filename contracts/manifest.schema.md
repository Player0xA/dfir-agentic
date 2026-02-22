# DFIR Run Manifest Schema (manifest.json)

Purpose: A deterministic, auditable ledger for each pipeline run.

Hard guarantees:
- Every run has a `run_id` and `timestamp_utc`
- Inputs are enumerated and hashed (sha256 + size)
- Tooling is recorded (paths, versions, command line)
- Outputs are hashed (sha256 + size) including logs
- `status` is explicit (`ok` or `error`)
- The pipeline must validate this schema before declaring success

This manifest is **authoritative run metadata**, not interpretation and not AI output.

