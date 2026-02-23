---
name: analyzing-timeline
description: Use this skill when you need to query the Plaso Super Timeline to correlate file system events, find file creation times, or verify execution artifacts within a specific time window.
---
# Timeline Analysis Instructions
You are equipped with the `dfir.query_super_timeline@1` MCP tool. 

## Workflow
1. Always establish the timestamp of the initial alert or suspicious event.
2. Query the timeline for ±5 minutes around that timestamp to establish context.
3. Identify relevant process executions, file creations, or network connections.
4. For advanced `psort` filtering syntax and common queries, see [psort_cheatsheet.md](file://.skills/analyzing-timeline/psort_cheatsheet.md).

## Critical Rules
- Never summarize more than 20 events at once to preserve context.
- Always use ISO8601 UTC format for timestamps.
