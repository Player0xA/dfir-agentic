# DFIR Findings Contract (Normative) — v1.0.0

## Scope

This document defines the canonical interface between:
1) deterministic DFIR pipelines (upstream producers), and
2) agentic reasoning + human review (downstream consumers).

This contract defines **structure and invariants**, not tool-specific content.

## Principles

- Tools produce facts; rules reduce entropy; agents reason; humans decide.
- Findings MUST be evidence-backed and atomic.
- Agents MUST NOT receive raw logs by default.
- The contract MUST be tool-agnostic and pipeline-agnostic.

## Top-level document

A pipeline run emits one document:

- `run_metadata` (required)
- `findings` (array)
- `requests` (array)

## run_metadata (required)

Purpose: provenance for the run context, reproducibility, and auditability.

Required fields:
- `run_id`: unique identifier per run
- `timestamp_utc`: ISO-8601 UTC timestamp of run start
- `environment`: runtime environment where pipeline executed (not the target host)
- `pipeline`: pipeline identity (not a tool), with version

Invariants:
- `run_metadata` is immutable once emitted.
- `run_id` MUST be unique per run. (UUID or content hash)
- `pipeline.name` MUST identify the pipeline spec, not the tool.

## findings[] (0..n)

A finding is a single, bounded observation backed by evidence references.

Required fields per finding:
- `finding_id`: unique within the run; stable for cross-linking
- `category`: normalized category (bounded enum)
- `summary`: one-sentence defensible statement
- `confidence`: confidence in correctness of the observation (data/rule quality)
- `severity`: operational priority/impact (separate from confidence)
- `source`: provenance (emitting tool/rule metadata)
- `evidence`: minimal references needed to rehydrate raw facts later
- `raw_refs`: pointers to raw storage locations/offsets (not raw content)

Invariants:
- Findings MUST be atomic (no bundles of unrelated events).
- Findings MUST be evidence-backed (at least one raw ref).
- Findings MUST NOT contain attribution, speculation, or conclusions beyond evidence.

## requests[] (0..n)

Requests represent explicit knowledge gaps to drive iterative collection/enrichment.

Required fields per request:
- `request_id`: unique within the run
- `type`: bounded enum (collection/enrichment/correlation/tool-run)
- `description`: explicit instruction
- `priority`: bounded enum
- `status`: bounded enum

Optional:
- `triggered_by`: finding_id that motivated the request
- `justification`: why this request exists (human-auditable)

Invariants:
- Requests may be appended by agents or humans.
- Pipelines may satisfy requests in later runs.
- Findings MUST NOT be rewritten; new info is a new finding.

## Contract stability

- Additive changes are allowed (new optional fields).
- Breaking changes require a version bump (v2.x).
