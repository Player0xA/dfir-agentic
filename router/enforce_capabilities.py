#!/usr/bin/env python3
import argparse
import fnmatch
import json
import sys
from pathlib import Path

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def norm_rel(p: str) -> str:
    # normalize to posix-ish relative path without leading './'
    s = str(Path(p))
    if s.startswith("./"):
        s = s[2:]
    return s

def deny(msg: str, code: int = 7) -> int:
    print(f"DENY: {msg}", file=sys.stderr)
    return code

def main() -> int:
    ap = argparse.ArgumentParser(description="Capability enforcement gate (pre-MCP)")
    ap.add_argument("--registry", default=".agents/registry.json")
    ap.add_argument("--agent-id", required=True)
    ap.add_argument("--action", required=True, choices=["dispatch_pipeline", "read_path"])
    ap.add_argument("--pipeline-id", default=None)
    ap.add_argument("--path", default=None)
    args = ap.parse_args()

    reg = load_json(Path(args.registry))
    agents = {a["agent_id"]: a for a in reg.get("agents", [])}
    if args.agent_id not in agents:
        return deny(f"unknown agent_id: {args.agent_id}", 3)

    caps = agents[args.agent_id]["capabilities"]

    if args.action == "dispatch_pipeline":
        if not args.pipeline_id:
            return deny("dispatch_pipeline requires --pipeline-id", 2)
        allowed = set(caps.get("can_dispatch_pipelines", []))
        if args.pipeline_id not in allowed:
            return deny(f"{args.agent_id} cannot dispatch pipeline '{args.pipeline_id}'")
        print("ALLOW")
        return 0

    if args.action == "read_path":
        if not args.path:
            return deny("read_path requires --path", 2)
        target = norm_rel(args.path)

        roots = [norm_rel(r) for r in caps.get("can_read_roots", [])]
        if not any(target == r or target.startswith(r.rstrip("/") + "/") for r in roots):
            return deny(f"{args.agent_id} read outside allowed roots: {target}")

        globs = caps.get("can_read_globs", [])
        # match against basename + full path patterns (flexible but controlled by roots)
        base = Path(target).name
        if not any(fnmatch.fnmatch(target, g) or fnmatch.fnmatch(base, g) for g in globs):
            return deny(f"{args.agent_id} path not allowed by globs: {target}")

        print("ALLOW")
        return 0

    return deny("unhandled action", 9)

if __name__ == "__main__":
    raise SystemExit(main())

