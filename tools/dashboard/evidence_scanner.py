#!/usr/bin/env python3
"""Evidence drop folder scanner and manager."""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import hashlib

# Default drop folder path - can be overridden via environment variable
DEFAULT_DROP_FOLDER = os.environ.get(
    "DFIR_EVIDENCE_DROP", 
    "/home/nevermore/evidence_drop"
)

# Evidence file patterns by category
EVIDENCE_PATTERNS = {
    "evtx": {
        "extensions": [".evtx", ".evt"],
        "description": "Windows Event Logs",
        "icon": "📋"
    },
    "registry": {
        "patterns": ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "NTUSER.DAT", "UsrClass.dat"],
        "extensions": [".hiv"],
        "description": "Windows Registry Hives",
        "icon": "🔐"
    },
    "mft": {
        "patterns": ["$MFT", "$MFTMirr"],
        "description": "Master File Table",
        "icon": "💿"
    },
    "memory": {
        "extensions": [".mem", ".raw", ".dmp", ".vmem", ".img"],
        "description": "Memory Dumps",
        "icon": "🧠"
    },
    "disk": {
        "extensions": [".e01", ".ex01", ".aff", ".aff4", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx"],
        "description": "Disk Images",
        "icon": "💾"
    },
    "network": {
        "extensions": [".pcap", ".pcapng", ".cap"],
        "description": "Network Captures",
        "icon": "🌐"
    },
    "logs": {
        "extensions": [".log", ".txt"],
        "patterns": ["auth.log", "syslog", "messages", "secure"],
        "description": "Log Files",
        "icon": "📝"
    },
    "forensic_artifacts": {
        "patterns": ["$LogFile", "$UsnJrnl", "$Secure", "$Boot", "$Bitmap"],
        "description": "Forensic Artifacts",
        "icon": "🔍"
    },
    "databases": {
        "extensions": [".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"],
        "description": "Database Files",
        "icon": "🗄️"
    },
    "misc": {
        "description": "Other Files",
        "icon": "📦"
    }
}


def get_drop_folder() -> Path:
    """Get the configured drop folder path."""
    return Path(DEFAULT_DROP_FOLDER)


def ensure_drop_folder() -> Path:
    """Ensure drop folder exists, create if not."""
    drop_folder = get_drop_folder()
    drop_folder.mkdir(parents=True, exist_ok=True)
    return drop_folder


def categorize_file(file_path: Path) -> str:
    """Categorize a file based on its name and extension."""
    name = file_path.name
    ext = file_path.suffix.lower()
    
    for category, patterns in EVIDENCE_PATTERNS.items():
        if category == "misc":
            continue
            
        # Check extensions
        if "extensions" in patterns:
            if ext in patterns["extensions"]:
                return category
        
        # Check filename patterns
        if "patterns" in patterns:
            for pattern in patterns["patterns"]:
                if pattern.lower() in name.lower():
                    return category
    
    return "misc"


def scan_folder(folder_path: Path, max_depth: int = 3, current_depth: int = 0) -> Dict:
    """Recursively scan a folder and categorize files."""
    result = {
        "path": str(folder_path),
        "name": folder_path.name,
        "type": "folder",
        "categories": {},
        "files": [],
        "subfolders": [],
        "total_files": 0,
        "size_bytes": 0,
        "last_modified": None
    }
    
    if current_depth > max_depth:
        return result
    
    try:
        for item in folder_path.iterdir():
            try:
                if item.is_file():
                    category = categorize_file(item)
                    file_info = {
                        "name": item.name,
                        "path": str(item),
                        "size": item.stat().st_size,
                        "category": category,
                        "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                    }
                    
                    result["files"].append(file_info)
                    result["total_files"] += 1
                    result["size_bytes"] += file_info["size"]
                    
                    # Track by category
                    if category not in result["categories"]:
                        result["categories"][category] = {
                            "count": 0,
                            "size": 0,
                            "files": []
                        }
                    result["categories"][category]["count"] += 1
                    result["categories"][category]["size"] += file_info["size"]
                    result["categories"][category]["files"].append(file_info)
                    
                elif item.is_dir() and not item.name.startswith("."):
                    subfolder = scan_folder(item, max_depth, current_depth + 1)
                    if subfolder["total_files"] > 0:  # Only include non-empty folders
                        result["subfolders"].append(subfolder)
                        result["total_files"] += subfolder["total_files"]
                        result["size_bytes"] += subfolder["size_bytes"]
                        
            except (PermissionError, OSError):
                continue
                
    except (PermissionError, OSError):
        pass
    
    # Get folder modification time
    try:
        stat = folder_path.stat()
        result["last_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    except:
        pass
    
    return result


def classify_evidence_folder(folder_data: Dict) -> Dict:
    """Classify an evidence folder based on its contents."""
    categories = folder_data.get("categories", {})
    
    classification = {
        "kind": "unknown",
        "confidence": "low",
        "description": "Unknown evidence type",
        "detected_categories": list(categories.keys()),
        "primary_category": None,
        "signals": []
    }
    
    # Windows Triage detection
    has_windows = any(cat in categories for cat in ["evtx", "registry", "mft"])
    has_users = any("Users" in str(f.get("path", "")) for f in folder_data.get("files", []))
    has_windows_folder = folder_data.get("name") == "Windows" or any("Windows" in str(f.get("path", "")) for f in folder_data.get("files", []))
    
    if has_windows and (has_users or has_windows_folder):
        classification["kind"] = "windows_triage_dir"
        classification["confidence"] = "high"
        classification["description"] = "Windows Triage Directory"
        classification["signals"].append("windows_system_detected")
        if "evtx" in categories:
            classification["signals"].append("evtx_present")
        if "registry" in categories:
            classification["signals"].append("registry_hives_detected")
        if "mft" in categories:
            classification["signals"].append("mft_detected")
    
    # EVTX-only
    elif "evtx" in categories and len(categories) == 1:
        classification["kind"] = "windows_evtx_dir"
        classification["confidence"] = "high"
        classification["description"] = "Windows Event Logs Directory"
        classification["signals"].append("evtx_only")
    
    # Memory dump
    elif "memory" in categories:
        classification["kind"] = "memory_dump_file"
        classification["confidence"] = "high"
        classification["description"] = "Memory Dump"
        classification["signals"].append("memory_detected")
    
    # Disk image
    elif "disk" in categories:
        classification["kind"] = "disk_image_file"
        classification["confidence"] = "high"
        classification["description"] = "Disk Image"
        classification["signals"].append("disk_image_detected")
    
    # Network capture
    elif "network" in categories:
        classification["kind"] = "pcap_file"
        classification["confidence"] = "high"
        classification["description"] = "Network Capture"
        classification["signals"].append("pcap_detected")
    
    # Set primary category
    if categories:
        classification["primary_category"] = max(categories.items(), key=lambda x: x[1]["count"])[0]
    
    return classification


def scan_drop_folder() -> Dict:
    """Scan the entire drop folder and return available evidence."""
    drop_folder = ensure_drop_folder()
    
    result = {
        "drop_folder": str(drop_folder),
        "scanned_at": datetime.now().isoformat(),
        "evidence_items": [],
        "summary": {
            "total_items": 0,
            "total_files": 0,
            "categories_found": set()
        }
    }
    
    # Scan immediate subfolders (organized by date/case)
    try:
        for item in sorted(drop_folder.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if item.is_dir() and not item.name.startswith("."):
                folder_data = scan_folder(item, max_depth=2)
                
                if folder_data["total_files"] > 0:
                    classification = classify_evidence_folder(folder_data)
                    
                    evidence_item = {
                        "id": hashlib.md5(str(item).encode()).hexdigest()[:12],
                        "name": item.name,
                        "path": str(item),
                        "type": "folder",
                        "classification": classification,
                        "stats": {
                            "total_files": folder_data["total_files"],
                            "size_bytes": folder_data["size_bytes"],
                            "categories": {k: v["count"] for k, v in folder_data["categories"].items()},
                            "last_modified": folder_data["last_modified"]
                        },
                        "preview": {
                            "categories": folder_data["categories"]
                        }
                    }
                    
                    result["evidence_items"].append(evidence_item)
                    result["summary"]["total_items"] += 1
                    result["summary"]["total_files"] += folder_data["total_files"]
                    result["summary"]["categories_found"].update(folder_data["categories"].keys())
                    
    except Exception as e:
        result["error"] = str(e)
    
    # Convert set to list for JSON serialization
    result["summary"]["categories_found"] = list(result["summary"]["categories_found"])
    
    return result


def get_evidence_details(evidence_path: str) -> Dict:
    """Get detailed information about specific evidence."""
    path = Path(evidence_path)
    
    if not path.exists():
        return {"error": "Path not found", "path": evidence_path}
    
    if path.is_file():
        category = categorize_file(path)
        return {
            "path": str(path),
            "name": path.name,
            "type": "file",
            "category": category,
            "size": path.stat().st_size,
            "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat()
        }
    
    # It's a folder - do full scan
    folder_data = scan_folder(path, max_depth=3)
    classification = classify_evidence_folder(folder_data)
    
    return {
        "path": str(path),
        "name": path.name,
        "type": "folder",
        "classification": classification,
        "stats": {
            "total_files": folder_data["total_files"],
            "size_bytes": folder_data["size_bytes"],
            "categories": {k: v["count"] for k, v in folder_data["categories"].items()}
        },
        "files_by_category": folder_data["categories"]
    }


if __name__ == "__main__":
    # Test the scanner
    print("Scanning drop folder...")
    results = scan_drop_folder()
    print(json.dumps(results, indent=2))
