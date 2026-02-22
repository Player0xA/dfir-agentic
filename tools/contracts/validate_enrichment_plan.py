#!/usr/bin/env python3
import json
import sys
from pathlib import Path

try:
    import jsonschema
except Exception:
    print("FAIL: missing dependency jsonschema (pip install jsonschema)", file=sys.stderr)
    raise

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <schema.json> <plan.json>", file=sys.stderr)
        return 2

    schema_path = Path(sys.argv[1])
    plan_path = Path(sys.argv[2])

    if not schema_path.is_file():
        print(f"FAIL: schema not found: {schema_path}", file=sys.stderr)
        return 2
    if not plan_path.is_file():
        print(f"FAIL: plan not found: {plan_path}", file=sys.stderr)
        return 2

    schema = load_json(schema_path)
    doc = load_json(plan_path)

    try:
        jsonschema.validate(instance=doc, schema=schema)
    except jsonschema.ValidationError as e:
        print("FAIL: document does not validate", file=sys.stderr)
        print(str(e), file=sys.stderr)
        return 2

    print("OK: plan validates")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

