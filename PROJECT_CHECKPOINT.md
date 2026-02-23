# Technical Checkpoint: DFIR Agentic Tri-Server Architecture

## Current State (v0.5)
The system has moved from a single script to a **Tri-Server Forensic Hub**. 

### 1. The Hub (`deepseek_orchestrator.py`)
- **Status**: Stable.
- **Capability**: Processes `intake.json`, routes multi-prefix tool calls (`dfir.`, `memory_`, `evtx_`), and manages AI escalation.
- **Tech Debt**: It currently operates in a "one-off" pass. It does not yet maintain a persistent state or "memory" of previous investigations across different runs.

### 2. The Deterministic Core (`dfir_mcp_server.py`)
- **Status**: Production-ready.
- **Logic**: Rule-based tiering (Quick/Deep).
- **Backend**: Plaso timeline extraction and Hayabusa triage integrated.
- **Capability**: Automated evidence identification and baseline processing.

### 3. The Forensic Spokes (`mcp-windows`, `mem-forensics-mcp`)
- **Status**: Integrated.
- **Capability**: Deep-dive Windows artifacts (Registry/EVTX) and high-speed Memory analysis.
- **Gap**: These spokes return JSON findings but are "case-agnostic". They don't know the case ID being handled by the Hub.

---

## The "Output Structure" Question
You asked if the output structure needs to change. **Realistic assessment: Yes.**

### The Current Friction:
Right now, the Core server writes to `outputs/intake/<ID>/`, but if you call a tool like `memory_dump_process`, the AI has to manually specify a path or it might default to the submodule's folder.

### Proposed Technical Alignment:
1.  **Unified Working Directory**: We should pass the `outputs/intake/<ID>/` path as a global context variable to all MCP servers.
2.  **Artifact Centralization**: All forensics artifacts (RAM dumps, strings, extracted hives) should be standardized into `outputs/forensics/<ID>/` instead of being scattered.
3.  **Audit Logs**: We need to unify the `mcp_runs/` audit logs so that we can see the full cross-server trace of what the AI did in a single folder.

---

## Milestone Summary
- [x] **Hub-and-Spoke Routing**: COMPLETE (Absolute path resolution verified).
- [x] **Forensic Breadth**: COMPLETE (Memory, Registry, EVTX, Timeline, YARA).
- [x] **Tiered Triage**: COMPLETE (Rule engine logic in `policy_engine.py`).
- [/] **Output Convergence**: IN PROGRESS (Need to unify case-ID passing).

**Verdict**: The "plumbing" is done. The next level of maturity is making the tools "Case Aware".
