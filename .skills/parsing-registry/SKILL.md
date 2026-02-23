---
name: parsing-registry
description: Use this skill when investigating persistence mechanisms, user activity, or system configuration within Windows Registry hives.
---
# Registry Analysis Instructions
You are equipped with tools to analyze Windows Registry hives (via `winforensics-mcp` or direct path reading).

## Workflow
1. Identify the relevant hive (SYSTEM, SOFTWARE, SAM, or NTUSER.DAT).
2. Locate common persistence keys (Run, RunOnce, Services).
3. Extract timestamps of key modifications (LastWriteTime).

## Common Keys to Check
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\System\CurrentControlSet\Services`
