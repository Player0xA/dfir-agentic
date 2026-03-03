# Forensic Project Memory (SIFT Workstation)

## Guardrails & Constraints
- **100KB Limit**: Treat outputs > 100KB as data sources, not context. Use surgical query tools.
- **Forensic Soundness**: Use read-only tools. Never modify original evidence paths.
- **Convergence Contract**: You MUST produce `root_cause_analysis.json` before exiting.

## Case Envelope (Absolute Paths)
- Timeline (Plaso): `CASE://54c69a3c-1ba6-44c2-9ece-52363fe1d1ff.plaso`
- Auto Enrichment: `CASE://auto.json`
- Findings: `CASE://case_findings.json`
- Case Manifest: `CASE://case_manifest.json`
- Summary: `CASE://case_summary.md`
- Intake Metadata: `CASE://intake.json`
- Timeline (Super): `CASE://54c69a3c-1ba6-44c2-9ece-52363fe1d1ff.plaso`
