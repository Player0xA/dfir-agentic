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
        eprint("Usage: validate_triage.py <triage.schema.json> <triage.json>")
        return 2

    schema_path = Path(sys.argv[1])
    triage_path = Path(sys.argv[2])

    if not schema_path.is_file():
        eprint(f"FAIL: schema not found: {schema_path}")
        return 2
    if not triage_path.is_file():
        eprint(f"FAIL: triage not found: {triage_path}")
        return 2

    try:
        schema = load_json(schema_path)
        triage = load_json(triage_path)
    except Exception as ex:
        eprint(f"FAIL: could not read JSON: {ex}")
        return 3

    try:
        import jsonschema
        from jsonschema import Draft202012Validator
    except Exception:
        eprint("FAIL: missing dependency 'jsonschema' (pip install jsonschema)")
        return 4

    try:
        Draft202012Validator.check_schema(schema)
    except Exception as ex:
        eprint(f"FAIL: invalid JSON Schema: {schema_path} ({ex})")
        return 5

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(triage), key=lambda e: e.path)

    if errors:
        eprint("FAIL: triage schema validation failed")
        for err in errors[:50]:
            loc = "$"
            for p in err.path:
                loc += f"[{p!r}]" if isinstance(p, str) else f"[{p}]"
            eprint(f"  - {loc}: {err.message}")
        if len(errors) > 50:
            eprint(f"  ... {len(errors) - 50} more errors")
        return 6

    print("OK: triage validated")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

