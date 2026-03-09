#!/usr/bin/env python3
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from tools.orchestrator.deepseek_orchestrator import auto_correct_epistemic_claims, validate_case_notes

def test_epistemic_leveling():
    print("--- Testing Phase 34 Auto-Epistemic Leveling ---")
    
    # Test Case 1: High-Inference Observation (Should be leveled)
    bad_args = {
        "claims": [
            {
                "claim_id": "CN-TEST-01",
                "type": "OBSERVATION",
                "statement": "The attacker performed lateral movement using PsExec.",
                "evidence_refs": ["CASE://evidence/staged/logs/security.evtx"],
                "status": "Open"
            }
        ],
        "next_steps": ["Verify credentials"]
    }
    
    print("[*] Case 1: Testing 'lateral movement' in OBSERVATION...")
    auto_correct_epistemic_claims(bad_args)
    
    leveled_type = bad_args["claims"][0]["type"]
    print(f"[*] Post-leveling type: {leveled_type}")
    
    if leveled_type != "HYPOTHESIS":
        print(f"FAIL: Claim was not leveled to HYPOTHESIS. Got: {leveled_type}")
        return
    
    # Test Case 2: Validation of leveled claim
    print("[*] Case 2: Validating the leveled claim...")
    is_valid, err_msg = validate_case_notes(bad_args)
    if not is_valid:
        print(f"FAIL: Valid leveled claim failed validation: {err_msg}")
        return
    
    # Test Case 3: Proper Hypothesis (Should remain HYPOTHESIS)
    good_args = {
        "claims": [
            {
                "claim_id": "CN-TEST-02",
                "type": "HYPOTHESIS",
                "statement": "The attacker may have persistence.",
                "evidence_refs": ["CASE://evidence/staged/logs/system.evtx"],
                "status": "Open"
            }
        ],
        "next_steps": ["Check Run keys"]
    }
    
    print("[*] Case 3: Testing existing HYPOTHESIS...")
    auto_correct_epistemic_claims(good_args)
    final_type = good_args["claims"][0]["type"]
    print(f"[*] Final type: {final_type}")
    if final_type != "HYPOTHESIS":
        print(f"FAIL: Existing HYPOTHESIS was changed. Got: {final_type}")
        return

    # Test Case 4: Low-Inference Observation (Should remain OBSERVATION)
    fact_args = {
        "claims": [
            {
                "claim_id": "CN-TEST-03",
                "type": "OBSERVATION",
                "statement": "File 'malicious.exe' was found in C:\\Temp.",
                "evidence_refs": ["CASE://evidence/staged/logs/security.evtx"],
                "status": "Open"
            }
        ],
        "next_steps": ["Analyze file"]
    }
    # Note: 'malicious' IS an inference keyword, so this SHOULD be leveled.
    print("[*] Case 4: Testing 'malicious' in OBSERVATION (should level)...")
    auto_correct_epistemic_claims(fact_args)
    if fact_args["claims"][0]["type"] != "HYPOTHESIS":
        print(f"FAIL: 'malicious' did not trigger leveling. Got: {fact_args['claims'][0]['type']}")
        return

    print("SUCCESS: Auto-Epistemic Leveling verified.")

if __name__ == "__main__":
    test_epistemic_leveling()
