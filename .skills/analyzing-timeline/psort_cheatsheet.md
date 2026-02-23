# Plaso psort Cheatsheet

The `query_super_timeline` tool uses the `psort` engine. Below are common filters you can use in the `artifact_filter` parameter.

## Filtering by Provider/Source
- Windows Event Logs: `parser is winevtx`
- File System MFT: `parser is filestat`
- Registry: `parser is winreg`

## Filtering by Content
- Find specific process: `message contains "cmd.exe"`
- Find specific file path: `filename contains "System32"`
- Find specific Event ID: `event_identifier is 4624`

## Combining Filters
- `parser is winevtx AND event_identifier is 4688`
- `parser is filestat AND filename contains "AppData/Roaming"`
