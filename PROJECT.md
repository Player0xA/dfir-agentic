# DFIR Agentic Workbench

## Purpose
This project builds an agentic DFIR automation system running inside a SIFT Workstation.
The system assists Incident Response and Threat Hunting workflows by orchestrating
deterministic forensic tools and escalating high-signal findings to reasoning agents.

## Operating Principles
- Deterministic tools first, AI second
- Evidence is read-only
- Humans remain in the loop
- Automation must be explainable and reproducible

## Data Philosophy
- CSV: human review
- JSONL: storage / streaming
- TOON: agent consumption
- Parquet: large-scale analytics

## Current Milestone
SIFT Workstation operational. Beginning agent bootstrap.

