# DFIR Findings Contract — v1.0

## Purpose

This document defines the canonical data contract between
deterministic DFIR pipelines and downstream agentic reasoning.

All agents MUST treat this contract as authoritative.
Agents MAY NOT infer facts not explicitly represented here.

---

## Top-Level Structure

```json
{
  "run_metadata": { ... },
  "findings": [ ... ],
  "requests": [ ... ]
}

