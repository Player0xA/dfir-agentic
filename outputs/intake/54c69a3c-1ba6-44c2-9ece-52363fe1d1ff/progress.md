
## 2026-03-03T22:50:29Z
- **[OBSERVATION]** (obs-001): Security audit logs were cleared on 2026-01-14T10:49:44.557632Z by user jasonr (SID: S-1-5-21-1841095656-2843128008-524542198-2677) from domain MILLSINC using process ID 5760 | Refs: `F-f5d1a29d-000006` | Conf: High | Status: Open
- **[OBSERVATION]** (obs-002): System logs were cleared on 2026-01-14T10:49:44.557632Z by user jasonr affecting both System and Windows PowerShell logs | Refs: `F-f5d1a29d-000004, F-f5d1a29d-000005` | Conf: High | Status: Open
- **[OBSERVATION]** (obs-003): Multiple external remote SMB logons from public IP 195.101.67.3 (source computer DCFS) targeting accounts TaskManager (SID: S-1-5-21-1841095656-2843128008-524542198-2921) and Administrator (SID: S-1-5-21-1841095656-2843128008-524542198-500) | Refs: `F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000127, F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000131, F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000140` | Conf: High | Status: Open
- **[HYPOTHESIS]** (hyp-001): The log clearing activity by jasonr at 10:49:44Z was likely an attempt to cover tracks after or during external SMB logon attempts from IP 195.101.67.3 starting at 11:41:03Z | Refs: `F-f5d1a29d-000006, F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000127` | Conf: Medium | Status: Open

### Next Steps
- Investigate process ID 5760 associated with log clearing
- Examine events around 2026-01-14T10:49:44Z to understand context of log clearing
- Investigate the external IP 195.101.67.3 for threat intelligence
- Check for other suspicious activities around the same timeframe

## 2026-03-03T22:52:35Z
- **[OBSERVATION]** (obs-004): PowerShell event log shows a PowerShell command was executed at 2026-01-14T10:49:44.573257Z with command: 'powershell $logs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount} | Select-Object -ExpandProperty LogName ; ForEach ( $l in $logs | Sort | Get-Unique ) {[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l)}' | Refs: `Windows PowerShell.evtx:EventID:403` | Conf: High | Status: Open
- **[DERIVED]** (der-001): The PowerShell command found in Windows PowerShell.evtx is a script designed to clear all Windows event logs that have record counts, matching the log clearing events observed in Security.evtx and System.evtx | Refs: `obs-004, obs-001, obs-002` | Conf: High | Status: Open
- **[HYPOTHESIS]** (hyp-002): User jasonr executed a PowerShell script to clear all Windows event logs at 10:49:44Z, which is a common anti-forensics technique to cover tracks | Refs: `obs-004, obs-001, obs-002` | Conf: High | Status: Open
- **[OBSERVATION]** (obs-005): Multiple external SMB logons from IP 195.101.67.3 (source computer DCFS) occurred starting at 11:41:03Z, approximately 52 minutes after the log clearing activity | Refs: `F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000127, F-893d610c-bb8e-4257-8ed7-c1bd80ae296d-000131` | Conf: High | Status: Open
- **[HYPOTHESIS]** (hyp-003): The log clearing at 10:49:44Z may have been preparatory activity before external attack attempts from IP 195.101.67.3 starting at 11:41:03Z | Refs: `obs-004, obs-005` | Conf: Medium | Status: Open

### Next Steps
- Check VirusTotal for IP 195.101.67.3 reputation
- Investigate if there were any successful logons after the external SMB attempts
- Examine other event logs for additional suspicious activity around the same timeframe
- Check for any file creation or modification events around the log clearing time
