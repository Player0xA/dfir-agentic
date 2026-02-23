#!/usr/bin/env python3
"""
DFIR Structured Policy Engine (Deterministic Router)

Evaluates triage findings against a predefined set of rules to determine
investigative depth (tiers) before initiating agentic reasoning.
"""

def evaluate(triage: dict, threshold_detections: int = 50) -> dict:
    # 1. High Severity Match
    # If any findings are high or critical, we immediately escalate to 'deep'.
    severity_counts = triage.get("counts", {}).get("by_severity", {})
    if severity_counts.get("critical", 0) > 0 or severity_counts.get("high", 0) > 0:
        return {
            "should_run": True,
            "tier": "deep",
            "reason": f"Escalation Rule: Critical/High severity findings present ({severity_counts})."
        }

    # 2. Category-Specific Match (e.g., Lateral Movement or Persistence)
    # These categories often warrant deeper inspection even if volume is low.
    category_counts = triage.get("counts", {}).get("by_category", {})
    escalation_categories = ["lateral_movement", "persistence", "credential_access"]
    triggered_cats = [cat for cat in escalation_categories if category_counts.get(cat, 0) > 0]
    
    if triggered_cats:
        return {
            "should_run": True,
            "tier": "deep",
            "reason": f"Escalation Rule: Sensitive categories detected: {triggered_cats}."
        }

    # 3. Volume-Based Match (Traditional Threshold)
    total_detections = triage.get("counts", {}).get("total_findings") or \
                       triage.get("counts", {}).get("total_detections") or 0
                       
    if total_detections >= threshold_detections:
        return {
            "should_run": True,
            "tier": "quick",
            "reason": f"Volume Rule: Detection count {total_detections} >= threshold {threshold_detections}."
        }

    # 4. Default Case
    return {
        "should_run": True,
        "tier": "quick",
        "reason": "Default Rule: Balanced scan for low-volume baseline."
    }
