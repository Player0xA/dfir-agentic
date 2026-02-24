#!/usr/bin/env python3
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from tools.orchestrator.deepseek_orchestrator import auto_correct_epistemic_claims, validate_case_notes

def test_v35_protocol():
    print("--- Testing Phase 35 Full Epistemic Protocol ---")
    
    # 1. Test Causal Structural Detection (led to)
    print("[*] Case 1: Testing causal 'led to' detection...")
    causal_args = {
        "claims": [
            {
                "claim_id": "CN-V35-01",
                "type": "OBSERVATION",
                "statement": "The process creation led to persistence.",
                "evidence_refs": ["CASE://evidence/staged/logs/security.evtx"]
            }
        ],
        "next_steps": ["Analyze persistence"]
    }
    auto_correct_epistemic_claims(causal_args)
    if causal_args["claims"][0]["type"] != "HYPOTHESIS":
        print(f"FAIL: 'led to' did not trigger HYPOTHESIS upgrade. Got: {causal_args['claims'][0]['type']}")
        return
    print(f"[OK] Upgraded to HYPOTHESIS. Status: {causal_args['claims'][0]['status']}, Conf: {causal_args['claims'][0]['confidence']}")

    # 2. Test GAP detection and Impact metadata
    print("[*] Case 2: Testing GAP detection and impact...")
    gap_args = {
        "claims": [
            {
                "claim_id": "CN-V35-02",
                "type": "UNKNOWN",
                "statement": "There is a logging gap in the security events.",
            }
        ],
        "next_steps": ["Check other log sources"]
    }
    auto_correct_epistemic_claims(gap_args)
    c_gap = gap_args["claims"][0]
    if c_gap["type"] != "GAP":
        print(f"FAIL: 'logging gap' did not trigger GAP type. Got: {c_gap['type']}")
        return
    if "impact" not in c_gap or c_gap["impact"] != "Medium":
        print(f"FAIL: GAP missing default impact. Got: {c_gap.get('impact')}")
        return
    if "confidence" in c_gap:
        print("FAIL: GAP should not have confidence field.")
        return
    print(f"[OK] Claim tagged as GAP. Impact: {c_gap['impact']}, Status: {c_gap['status']}")

    # 3. Test ASSESSMENT type and defaults
    print("[*] Case 3: Testing ASSESSMENT defaults...")
    assess_args = {
        "claims": [
            {
                "claim_id": "CN-V35-03",
                "type": "ASSESSMENT",
                "statement": "Lateral movement is the most probable root cause.",
            }
        ],
        "next_steps": ["Finalize report"]
    }
    auto_correct_epistemic_claims(assess_args)
    c_assess = assess_args["claims"][0]
    if c_assess["confidence"] != "Medium":
        print(f"FAIL: ASSESSMENT missing default confidence. Got: {c_assess['confidence']}")
        return
    print(f"[OK] ASSESSMENT validated. Conf: {c_assess['confidence']}, Status: {c_assess['status']}")

    # 4. Test DERIVED defaults
    print("[*] Case 4: Testing DERIVED defaults...")
    derived_args = {
        "claims": [
            {
                "claim_id": "CN-V35-04",
                "type": "DERIVED",
                "statement": "Calculated time delta is 5 minutes.",
                "evidence_refs": ["Ref-1", "Ref-2"]
            }
        ],
        "next_steps": ["Continue"]
    }
    auto_correct_epistemic_claims(derived_args)
    c_derived = derived_args["claims"][0]
    if c_derived["confidence"] != "High":
        print(f"FAIL: DERIVED missing High confidence. Got: {c_derived['confidence']}")
        return
    print(f"[OK] DERIVED validated. Conf: {c_derived['confidence']}")

    # 5. Schema Validation Check
    print("[*] Case 5: Final Schema Validation Check...")
    # Add status and refs where missing if necessary to pass strict validate_case_notes
    is_valid, err_msg = validate_case_notes(causal_args)
    if not is_valid:
        print(f"FAIL: Causal args failed validation: {err_msg}")
        return
    
    is_valid, err_msg = validate_case_notes(gap_args)
    if not is_valid:
        print(f"FAIL: GAP args failed validation: {err_msg}")
        return

    print("SUCCESS: Full Epistemic Protocol (V35) verified.")

if __name__ == "__main__":
    test_v35_protocol()
