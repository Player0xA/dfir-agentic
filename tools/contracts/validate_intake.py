#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def eprint(*args):
    print(*args, file=sys.stderr)

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def main() -> int:
    if len(sys.argv) != 3:
        eprint("Usage: validate_intake.py <intake.schema.json> <intake.json>")
        return 2

    schema_path = Path(sys.argv[1])
    doc_path = Path(sys.argv[2])

    if not schema_path.is_file():
        eprint(f"FAIL: schema not found: {schema_path}")
        return 2
    if not doc_path.is_file():
        eprint(f"FAIL: document not found: {doc_path}")
        return 2

    try:
        schema = load_json(schema_path)
        doc = load_json(doc_path)
    except Exception as ex:
        eprint(f"FAIL: could not read JSON: {ex}")
        return 3

    try:
        from jsonschema import Draft202012Validator
    except Exception:
        eprint("FAIL: missing dependency 'jsonschema' (pip install jsonschema)")
        return 4

    try:
        Draft202012Validator.check_schema(schema)
    except Exception as ex:
        eprint(f"FAIL: invalid JSON Schema: {schema_path} ({ex})")
        return 5

    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(doc), key=lambda e: e.path)
    if errors:
        eprint("FAIL: intake schema validation failed")
        for err in errors[:50]:
            loc = "$"
            for p in err.path:
                loc += f"[{p!r}]" if isinstance(p, str) else f"[{p}]"
            eprint(f"  - {loc}: {err.message}")
        if len(errors) > 50:
            eprint(f"  ... {len(errors) - 50} more errors")
        return 6

    print("OK: intake validated")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

