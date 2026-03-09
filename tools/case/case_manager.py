#!/usr/bin/env python3
import json
import os
import shutil
import uuid
import pathlib
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

class CaseManager:
    """
    Enforces the Canonical Case Layout (V26).
    Structure:
    /cases/<case_id>/
      case.json
      evidence/
        original/
        staged/
      outputs/
      manifests/
      logs/
    """
    def __init__(self, case_root: str | pathlib.Path):
        self.case_root = pathlib.Path(case_root).resolve()
        self.case_json_path = self.case_root / "case.json"
        self.evidence_root = self.case_root / "evidence"
        self.original_root = self.evidence_root / "original"
        self.staged_root = self.evidence_root / "staged"
        self.outputs_root = self.case_root / "outputs"
        self.manifest_root = self.case_root / "manifests"
        self.logs_root = self.case_root / "logs"

    def init_case(self, case_id: str) -> Dict[str, Any]:
        """Initialize the directory structure and create case.json."""
        dirs = [
            self.case_root,
            self.evidence_root,
            self.original_root,
            self.staged_root,
            self.outputs_root,
            self.manifest_root,
            self.logs_root,
            self.outputs_root / "intake",
            self.outputs_root / "deterministic",
            self.outputs_root / "orchestrator",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        case_meta = {
            "case_id": case_id,
            "case_root": str(self.case_root),
            "evidence_roots": {
                "original": str(self.original_root),
                "staged": str(self.staged_root)
            },
            "default_evidence_root": "staged",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "policy": {
                "immutable_original": True,
                "allow_symlinks_in_staged": True
            },
            "evidence": []
        }
        
        self._write_case_json(case_meta)
        return case_meta

    def load_case(self) -> Dict[str, Any]:
        if not self.case_json_path.exists():
            raise FileNotFoundError(f"case.json not found at {self.case_json_path}")
        return json.loads(self.case_json_path.read_text(encoding="utf-8"))

    def _write_case_json(self, data: Dict[str, Any]):
        self.case_json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def hash_file(self, path: pathlib.Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def generate_manifest(self, root_dir: pathlib.Path, manifest_name: str) -> Dict[str, Any]:
        """Generate a manifest of all files in a directory, following symlinks."""
        manifest = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "root": str(root_dir),
            "files": []
        }
        
        # Use os.walk with followlinks=True to ensure staged symlinks are inventoried
        for root, dirs, files in os.walk(root_dir, followlinks=True):
            for filename in files:
                p = pathlib.Path(root) / filename
                rel = p.relative_to(root_dir)
                manifest["files"].append({
                    "relpath": str(rel),
                    "size_bytes": p.stat().st_size,
                    "sha256": self.hash_file(p)
                })
        
        manifest_path = self.manifest_root / manifest_name
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def add_evidence(self, source_path: str | pathlib.Path, evidence_id: str, artifact_type: str, relpath: Optional[str] = None) -> Dict[str, Any]:
        """
        1. Copy source to evidence/original (immutable policy).
        2. Hash original.
        3. Symlink/Staging to evidence/staged.
        4. Update manifests and case.json.
        """
        source = pathlib.Path(source_path).resolve()
        if not source.exists():
            raise FileNotFoundError(f"Source evidence not found: {source}")

        # Target in original
        target_name = source.name
        original_target = self.original_root / target_name
        
        # Rule: evidence/original is read-only (once data is there)
        if not original_target.exists():
            if source.is_dir():
                shutil.copytree(source, original_target)
            else:
                shutil.copy2(source, original_target)
        
        # Hash and manifest original
        self.generate_manifest(self.original_root, "evidence.manifest.json")
        
        # Rule: evidence/staged is where we normalize layout
        if not relpath:
            relpath = target_name
            
        staged_target = self.staged_root / relpath
        staged_target.parent.mkdir(parents=True, exist_ok=True)
        
        if staged_target.exists() or staged_target.is_symlink():
            if staged_target.is_dir() and not staged_target.is_symlink():
                shutil.rmtree(staged_target)
            else:
                staged_target.unlink()
            
        # Create symlink from original to staged
        try:
            os.symlink(original_target, staged_target)
        except OSError:
            if original_target.is_dir():
                shutil.copytree(original_target, staged_target)
            else:
                shutil.copy2(original_target, staged_target)

        # Hash and manifest staged
        self.generate_manifest(self.staged_root, "staged.manifest.json")

        # Update case.json
        case_data = self.load_case()
        item = {
            "evidence_id": evidence_id,
            "type": artifact_type,
            "root": "staged",
            "relpath": str(relpath),
            "original_name": target_name,
            "added_utc": datetime.now(timezone.utc).isoformat(),
            "manifest_refs": {
                "original": "manifests/evidence.manifest.json",
                "staged": "manifests/staged.manifest.json"
            }
        }
        
        case_data["evidence"] = [e for e in case_data["evidence"] if e["evidence_id"] != evidence_id]
        case_data["evidence"].append(item)
        
        self._write_case_json(case_data)
        return item

if __name__ == "__main__":
    # Internal test/CLI
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--case-root", required=True)
    parser.add_argument("--case-id", default="unnamed-case")
    parser.add_argument("--add-evidence", help="path to source")
    parser.add_argument("--evidence-id", help="unique id for artifact")
    parser.add_argument("--type", help="artifact type (e.g. evtx_dir)")
    parser.add_argument("--relpath", help="normalized path in staged")
    
    args = parser.parse_args()
    cm = CaseManager(args.case_root)
    
    if args.init:
        print(f"[*] Initializing case {args.case_id} at {args.case_root}")
        cm.init_case(args.case_id)
        
    if args.add_evidence:
        if not args.evidence_id or not args.type:
            print("[!] --evidence-id and --type required when adding evidence")
            exit(1)
        print(f"[*] Adding evidence {args.add_evidence} as {args.evidence_id}")
        cm.add_evidence(args.add_evidence, args.evidence_id, args.type, args.relpath)
