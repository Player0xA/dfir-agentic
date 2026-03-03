# Enterprise Verification Guide (Phases 53-55)

Follow these steps on your **testing host** to verify that the forensic audit and governance layers are functioning correctly.

### 🧪 Test 1: Verify LLM Audit Ledger (Phase 53)
Run an autonomous investigation.
```bash
python3 dfir.py [raw_evidence_path] --auto --task "Brief triage" --mode autonomous
```
**Verification:**
1. Navigate to the orchestrator output directory: `outputs/intake/[uuid]/orchestrator/[run_id]/`.
2. check for `audit_ledger.jsonl`.
3. Run: `cat audit_ledger.jsonl | head -n 1 | jq .`
4. **Pass Criteria:** You should see the `prompt_payload` (exact prompt), `context_hash`, and the `raw_response` from the LLM.

### 🧪 Test 2: Verify Deterministic Replay (Phase 54)
Using the ledger from Test 1, let's prove the AI can reproduce its logic.
```bash
python3 tools/orchestrator/replay_turn.py --ledger [path_to_ledger] --iteration 1
```
**Verification:**
1. Observe the terminal output. It will fetch the iteration 1 payload and re-dispatch it.
2. **Pass Criteria:** If using a local model with temperature 0.0, you should see `[+] CERTIFIED: Cryptographic Determinism Achieved`.
3. check for `replay_certification_iter_1.md` in the same directory.

### 🧪 Test 3: Verify Skill Governance (Phase 55)
Trigger a skill load and check the cryptographic provenance.
1. Run a task that requires a specific skill (e.g., if you have a `memory_analysis` skill):
```bash
python3 dfir.py [memory_dump] --auto --task "Use the memory_analysis skill to check processes"
```
**Verification:**
1. check the `case_manifest.json` in the intake directory.
2. Run: `jq '.".governance.skills_used"' outputs/intake/[uuid]/case_manifest.json`
3. **Pass Criteria:** You should find an entry with the `skill_name`, a `version_hash` (matching the hash shown in the orchestrator registry), and a `loaded_utc` timestamp.

---

### Summary Checklist
- [ ] `audit_ledger.jsonl` contains raw transactions.
- [ ] `replay_turn.py` successfully matches hashes for identical inputs.
- [ ] `case_manifest.json` records SHA256 fingerprints of every skill instruction presented to the AI.
