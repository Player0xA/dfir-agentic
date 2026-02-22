#!/usr/bin/env python3
import json, sys
from jsonschema import Draft202012Validator

def main():
    if len(sys.argv) != 3:
        print("Usage: validate_findings.py <schema.json> <doc.json>", file=sys.stderr)
        return 2

    schema_path, doc_path = sys.argv[1], sys.argv[2]
    schema = json.load(open(schema_path))
    doc = json.load(open(doc_path))
    Draft202012Validator.check_schema(schema)
    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(doc), key=lambda e: (list(e.path), e.message))

    if errors:
        print(f"VALIDATION FAILED: {len(errors)} error(s)")
        for e in errors[:200]:
            path = "$"
            for p in e.path:
                path += f"[{p!r}]" if isinstance(p, int) else f".{p}"
            print(f"- {path}: {e.message}")
        return 1

    print("OK: document validates")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
