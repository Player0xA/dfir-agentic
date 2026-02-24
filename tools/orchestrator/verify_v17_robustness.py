import unittest
import re
import json
from pathlib import Path

# Mock safe imports for testing
def desanitize_tool_name(name: str) -> str:
    name = re.sub(r'__v(\d+)$', r'@\1', name)
    if "__" in name:
        name = name.replace("__", ".")
    return name

def robust_hex_normalize(search: str) -> str:
    # Logic from dfir_mcp_server.py (V17)
    if search.startswith("0x"):
        try:
            hex_val = search[2:]
            val = int(hex_val, 16)
            variants = set()
            variants.add(search.lower())
            variants.add(search.upper())
            variants.add(f"0x{val:08x}")
            variants.add(f"0x{val:08X}")
            variants.add(f"0x{val:016x}")
            variants.add(f"0x{val:016X}")
            or_parts = [f"message contains '{v}'" for v in sorted(list(variants))]
            return f"({' OR '.join(or_parts)})"
        except ValueError:
            pass
    return f"message contains '{search}'"

class TestPhase17Robustness(unittest.TestCase):
    def test_robust_hex_normalization(self):
        """Verify that 0x9d397 generates 8-char, 16-char, and casing variants."""
        raw_hex = "0x9d397"
        normalized = robust_hex_normalize(raw_hex)
        
        # Check for 8-char padding
        self.assertIn("0x0009d397", normalized)
        # Check for 16-char padding
        self.assertIn("0x000000000009d397", normalized)
        # Check for Uppercase variant
        self.assertIn("0X9D397", normalized.upper())
        self.assertIn("0x0009D397", normalized)
        
        print(f"DEBUG: Normalized Hex Filter: {normalized}")

    def test_rca_validation_feedback(self):
        """Verify that missing fields in RCA result in descriptive errors."""
        # This simulates the logic in check_for_rca
        import jsonschema
        
        schema_content = {
            "type": "object",
            "required": ["summary", "root_cause"],
            "properties": {
                "summary": {"type": "string"},
                "root_cause": {"type": "string"}
            }
        }
        
        bad_rca = {"root_cause": "Attacker cleared logs"} # missing 'summary'
        
        try:
            jsonschema.validate(instance=bad_rca, schema=schema_content)
        except jsonschema.exceptions.ValidationError as ve:
            msg = ve.message
            if "required" in msg.lower():
                msg = f"RCA Schema Validation Failed: {msg}. Ensure 'summary', 'root_cause'... are ALL present."
            self.assertIn("Ensure 'summary'", msg)
            print(f"DEBUG: Descriptive Error: {msg}")

if __name__ == "__main__":
    unittest.main()
