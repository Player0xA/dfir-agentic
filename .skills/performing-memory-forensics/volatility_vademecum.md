# Volatility 3 Vademecum

When using the `memory_run_volatility` tool, you must provide the correct plugin name.

## Process Identification
- `windows.pslist.PsList`: Standard process list (linked list).
- `windows.psscan.PsScan`: Scans for process blocks (finds unlinked/hidden processes).
- `windows.pstree.PsTree`: Visual parent-child relationship tree.

## Network & Injections
- `windows.netstat.NetStat`: Active network connections.
- `windows.malfind.Malfind`: Finds injected/hidden code blocks (VAD tags).
- `windows.handles.Handles`: Lists open mutant/file/registry handles for a specific `--pid`.

## Syntax Examples
If the tool requires an argument string:
- `["windows.malfind.Malfind", "--pid", "1234"]`
- `["windows.pslist.PsList"]`
