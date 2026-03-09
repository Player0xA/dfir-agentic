import os
import sys
import json
import subprocess
from pathlib import Path

def check_python_lib(name, import_name=None):
    if import_name is None:
        import_name = name
    try:
        subprocess.check_output([sys.executable, "-c", f"import {import_name}"], stderr=subprocess.STDOUT)
        return True, "Installed"
    except subprocess.CalledProcessError as e:
        return False, f"Missing: {e.output.decode().strip()}"

def check_binary(name):
    try:
        path = subprocess.check_output(["which", name]).decode().strip()
        return True, path
    except:
        return False, "Not Found"

def audit_mcp_stack():
    print("="*60)
    print("      COMPREHENSIVE MCP INTEGRITY AUDIT (V20)      ")
    print("="*60)
    
    print(f"\n[ENVIRONMENT]")
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    print(f"CWD: {os.getcwd()}")
    
    # 1. Forensic Libraries
    print(f"\n[FORENSIC LIBRARIES]")
    libs = {
        "python-evtx": "Evtx",
        "python-registry": "Registry",
        "jsonschema": "jsonschema",
        "json-repair": "json_repair",
        "yara-python": "yara",
        "volatility3": "volatility3"
    }
    
    results = {}
    for pkg, imp in libs.items():
        ok, status = check_python_lib(pkg, imp)
        results[pkg] = ok
        print(f"{' [OK]' if ok else ' [!!]'} {pkg:<20} -> {status}")

    # 2. Binary Dependencies
    print(f"\n[BINARY DEPENDENCIES]")
    bins = ["hayabusa", "psort.py", "log2timeline.py", "uv"]
    for b in bins:
        ok, path = check_binary(b)
        print(f"{' [OK]' if ok else ' [!!]'} {b:<20} -> {path}")

    # 3. Pathing & Bridge Audit
    print(f"\n[PATHING & BRIDGE AUDIT]")
    bridge_path = Path("tools/mcp/mcp-windows/winforensics-mcp")
    if bridge_path.exists():
        print(f" [OK] Bridge Root: {bridge_path.absolute()}")
        # Check submodules
        sys.path.append(str(bridge_path.absolute()))
        try:
            from winforensics_mcp.parsers import evtx_parser
            print(f" [OK] evtx_parser import: SUCCESS")
        except Exception as e:
            print(f" [!!] evtx_parser import: FAIL ({e})")
    else:
        print(f" [!!] Bridge Root: NOT FOUND ({bridge_path})")

    # 4. Memory MCP Check
    mem_path = Path("tools/mcp/memory/mem_forensics-mcp")
    if mem_path.exists():
        print(f" [OK] Memory MCP Root: {mem_path.absolute()}")
    else:
        print(f" [!!] Memory MCP Root: NOT FOUND")

    print("\n" + "="*60)
    if all(results.values()):
        print(" [SUMMARY] System is FULLY PRODUCTION READY.")
        return True
    else:
        print(" [SUMMARY] CRITICAL DEPENDENCIES MISSING.")
        print(" Suggestion: Run 'python3 -m pip install --user --break-system-packages python-evtx python-registry jsonschema json-repair'")
        return False

if __name__ == "__main__":
    if not audit_mcp_stack():
        sys.exit(1)
    sys.exit(0)
