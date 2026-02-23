# Plaso psort Cheatsheet

The `query_super_timeline` tool uses the `psort` engine. Below are common filters.

## ⚠️ PRO-TIP: Quotation Marks
Always wrap your filter strings in double quotes if they contain spaces. 
Example: `source_name contains "PowerShell"`

## Filtering by Provider/Source
- Windows Event Logs: `parser is winevtx`
- File System MFT: `parser is filestat`
- Registry: `parser is winreg`

## Filtering by Content
- Find specific process: `message contains "cmd.exe"`
- Find specific file path: `filename contains "System32"`
- Find specific Event ID: `event_identifier is 4624`
- Filter by Source: `source_name contains "Microsoft-Windows-PowerShell"`

## Combining Filters
- `parser is winevtx AND event_identifier is 4688`
- `parser is winevtx AND source_name contains "PowerShell"`
- `parser is filestat AND filename contains "AppData/Roaming"`
