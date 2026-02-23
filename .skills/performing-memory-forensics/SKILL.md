---
name: performing-memory-forensics
description: Use this skill when investigating active memory dumps (RAM/vmem), detecting injected code, analyzing running processes, or finding hidden network connections.
---
# Memory Forensics Instructions
You are equipped with tools to analyze RAM dumps via the `mem_forensics-mcp` backend server.

## Workflow
1. Use `memory_get_status` or `memory_analyze_dump` to establish a baseline of the memory image.
2. Identify suspicious processes using `memory_list_processes` or the `windows.pslist.PsList` Volatility plugin.
3. For deep analysis, you can execute raw Volatility 3 plugins using `memory_run_volatility`.
4. For advanced Volatility 3 syntax and a reference of useful plugins, see [volatility_vademecum.md](file://.skills/performing-memory-forensics/volatility_vademecum.md).

## Critical Rules
- Memory analysis can take time; be specific with your queries.
- Process IDs (PIDs) are the primary key linking memory artifacts. Always extract the PID.
