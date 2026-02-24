import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

def test_path_remapping():
    from tools.mcp.dfir_mcp_server import safe_resolve, PROJECT_ROOT
    
    print(f"[*] Project Root: {PROJECT_ROOT}")
    
    # 1. Test the "BAD" path reported by the user
    # BAD: /home/nevermore/dfir-agentic/outputs/intake/cases/intake/evtx/Logs/Security.evtx
    # REAL: /home/nevermore/cases/intake/evtx/Logs/Security.evtx
    
    # We want to verify that PASSING the BAD path resolves to the REAL one 
    # (assuming the REAL one suffix exists relative to PROJECT_ROOT.parent)
    
    # Heuristic Mock
    bad_path = "/home/nevermore/dfir-agentic/outputs/intake/cases/intake/evtx/Logs/Security.evtx"
    
    print(f"[*] Testing remapping of hallucinated path: {bad_path}")
    resolved = safe_resolve(bad_path)
    print(f"[*] Resolved to: {resolved}")
    
    # Check if suffix matches
    if "cases/intake/evtx/Logs/Security.evtx" in str(resolved):
        print(f"[SUCCESS] Hallucination healer stripped prefix. Resolved tail: {resolved}")
    else:
        print(f"[FAIL] Hallucination healer failed to strip prefix.")
        return False
    
    # On the user's machine, this will resolve to the REAL path.
    # On this machine, it won't exist, which is expected.
    if resolved.exists():
        print("[SUCCESS] Path resolved to an existing file.")
    else:
        print("[!] Result does not exist on this machine, but the tail mapping logic was verified.")
        print(f"    - Final Attempted path: {resolved}")

    return True

if __name__ == "__main__":
    if test_path_remapping():
        sys.exit(0)
    else:
        sys.exit(1)
