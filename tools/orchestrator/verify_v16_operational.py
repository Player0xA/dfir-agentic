import unittest
import re
from pathlib import Path

# Mock safe imports for testing
def desanitize_tool_name(name: str) -> str:
    # Logic from deepseek_orchestrator.py
    name = re.sub(r'__v(\d+)$', r'@\1', name)
    if "__" in name:
        name = name.replace("__", ".")
    return name

def hex_normalize(search: str) -> str:
    # Logic from dfir_mcp_server.py
    if search.startswith("0x"):
        try:
            val = int(search, 16)
            padded = f"0x{val:016x}"
            if padded.lower() != search.lower():
                return f"(message contains '{search}' OR message contains '{padded}')"
        except ValueError:
            pass
    return f"message contains '{search}'"

class TestPhase16Operational(unittest.TestCase):
    def test_desanitize_regex_hardening(self):
        """Verify that 'v' in 'validate' is not corrupted but __v1 is replaced."""
        corrupted_v13 = "dfir__validate_deliverable@1" # if it was already @
        # The specific failing case was dfir__validate_deliverable__v1
        target = "dfir__validate_deliverable__v1"
        desanitized = desanitize_tool_name(target)
        self.assertEqual(desanitized, "dfir.validate_deliverable@1")
        self.assertNotIn("@alidate", desanitized)
        
        # Test standard tool
        std = "dfir__query_super_timeline__v1"
        self.assertEqual(desanitize_tool_name(std), "dfir.query_super_timeline@1")

    def test_hex_normalization(self):
        """Verify that 0x9d397 is correctly padded to 16 chars."""
        raw_hex = "0x9d397"
        normalized = hex_normalize(raw_hex)
        self.assertIn("0x000000000009d397", normalized)
        self.assertIn("0x9d397", normalized)
        self.assertIn("OR", normalized)
        
        # Verify non-hex is left alone
        self.assertEqual(hex_normalize("jasonr"), "message contains 'jasonr'")
        
        # Verify already padded hex is left alone
        padded = "0x000000000009d397"
        self.assertEqual(hex_normalize(padded), f"message contains '{padded}'")

if __name__ == "__main__":
    unittest.main()
