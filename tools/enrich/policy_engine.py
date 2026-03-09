#!/usr/bin/env python3
"""
DFIR Structured Policy Engine (Deterministic Router)

Evaluates triage findings against a predefined set of rules to determine
investigative depth (tiers) before initiating agentic reasoning.
"""

def evaluate(triage: dict, threshold_detections: int = 50) -> dict:
    # Result structure
    decision = {
        "should_run": True,
        "tier": "quick",
        "reason": "Default Rule: Balanced scan for low-volume baseline.",
        "recommendations": []
    }

    # Helper: Recommended 10m window (5m before, 5m after)
    def get_slice(iso_str):
        try:
            from datetime import datetime, timedelta
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            start = (dt - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end = (dt + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return start, end
        except:
            return None, None

    # 1. High Severity Match
    severity_counts = triage.get("counts", {}).get("by_severity", {})
    if severity_counts.get("critical", 0) > 0 or severity_counts.get("high", 0) > 0:
        decision["tier"] = "deep"
        decision["reason"] = f"Escalation Rule: Critical/High severity findings present ({severity_counts})."
        
        bounds = triage.get("time_bounds", {})
        if bounds.get("min_first_seen"):
            s, e = get_slice(bounds["min_first_seen"])
            if s:
                decision["recommendations"].append({
                    "action": "dfir.query_super_timeline@1",
                    "description": "High severity alerts. Inspecting temporal window around first discovery.",
                    "params": {"start_time": s, "end_time": e}
                })

    # 2. Category-Specific Match (e.g., Lateral Movement or Persistence)
    category_counts = triage.get("counts", {}).get("by_category", {})
    escalation_categories = ["lateral_movement", "persistence", "credential_access"]
    triggered_cats = [cat for cat in escalation_categories if category_counts.get(cat, 0) > 0]
    
    if triggered_cats:
        decision["tier"] = "deep"
        if "Escalation" not in decision["reason"]:
            decision["reason"] = f"Escalation Rule: Sensitive categories detected: {triggered_cats}."
        
        if not decision["recommendations"]:
            bounds = triage.get("time_bounds", {})
            if bounds.get("min_first_seen"):
                s, e = get_slice(bounds["min_first_seen"])
                if s:
                    decision["recommendations"].append({
                        "action": "dfir.query_super_timeline@1",
                        "description": f"Sensitive categories {triggered_cats} detected. Inspecting timeline.",
                        "params": {"start_time": s, "end_time": e}
                    })

    # 3. Volume-Based Match (Traditional Threshold)
    total_detections = triage.get("counts", {}).get("total_findings") or \
                       triage.get("counts", {}).get("total_detections") or 0
                       
    if total_detections >= threshold_detections and decision["tier"] == "quick":
        decision["tier"] = "quick" # Stay quick but update reason
        decision["reason"] = f"Volume Rule: Detection count {total_detections} >= threshold {threshold_detections}."

    return decision
