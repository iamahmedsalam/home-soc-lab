# Incident Report IR-001 — PowerShell Encoded Command Execution

## Executive Summary

A PowerShell process was detected executing with the `-EncodedCommand` parameter on the Windows 11 SOC endpoint (192.168.56.103) on April 5, 2026. The encoded command is a common adversary technique used to obfuscate malicious payloads and evade string-based detection. Custom Wazuh Rule 100001 fired within 5 seconds of execution, generating a Level 10 (High) alert mapped to MITRE ATT&CK technique T1059.001.

## Classification

| Field | Value |
|---|---|
| **Report ID** | IR-001 |
| **Date** | April 5, 2026 |
| **Severity** | High (Level 10) |
| **MITRE ATT&CK** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Rule Triggered** | 100001 |
| **Agent** | WIN11-SOC-Endpoint (Agent 001) |
| **Agent IP** | 192.168.56.103 |
| **Status** | Closed — Simulated attack (Atomic Red Team) |

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-05 09:45:00 | Atomic Red Team test initiated on Windows 11 endpoint |
| 2026-04-05 09:45:01 | PowerShell.exe launched with `-EncodedCommand` parameter |
| 2026-04-05 09:45:01 | Sysmon Event ID 1 (Process Creation) logged with full command line |
| 2026-04-05 09:45:02 | Wazuh Agent 001 forwarded event to Wazuh Manager |
| 2026-04-05 09:45:03 | Rule 100001 matched — alert generated in Wazuh dashboard |
| 2026-04-05 09:45:05 | Alert visible in dashboard with MITRE ATT&CK mapping |

## Evidence

The following fields were extracted from the Wazuh alert:

| Field | Value |
|---|---|
| `rule.id` | 100001 |
| `rule.level` | 10 |
| `rule.description` | PowerShell encoded command execution detected (T1059.001) |
| `agent.name` | WIN11-SOC-Endpoint |
| `agent.id` | 001 |
| `agent.ip` | 192.168.56.103 |
| `data.win.system.eventID` | 1 |
| `data.win.system.channel` | Microsoft-Windows-Sysmon/Operational |
| `data.win.eventdata.image` | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| `data.win.eventdata.commandLine` | powershell.exe -EncodedCommand [Base64 string] |
| `data.win.eventdata.parentImage` | C:\Windows\System32\cmd.exe |
| `data.win.eventdata.user` | WIN11-SOC-Endpoint\Jackal |

## Investigation

**Step 1 — Alert triage:** Alert appeared in Wazuh dashboard under `rule.id: 100001`. Severity Level 10 (High) confirmed this requires immediate investigation.

**Step 2 — Command analysis:** The `commandLine` field showed `powershell.exe` launched with `-EncodedCommand` followed by a Base64-encoded string. In a production environment, the next step would be decoding the Base64 payload to determine the actual command executed.

**Step 3 — Parent process review:** The parent process was `cmd.exe`, indicating PowerShell was spawned from a command prompt. In a real incident, this chain would be traced further back to determine what launched `cmd.exe`.

**Step 4 — User context:** The process ran under `WIN11-SOC-Endpoint\Jackal` — a local user account. In production, this would be cross-referenced with HR/identity records to determine if the user had a legitimate reason for running encoded PowerShell.

**Step 5 — Sysmon hash verification:** Sysmon Event 1 includes SHA256 hashes of the executing binary. In production, these would be checked against threat intelligence feeds and VirusTotal.

## Root Cause

MITRE ATT&CK Technique **T1059.001 — Command and Scripting Interpreter: PowerShell**. The encoded command parameter allows attackers to pass Base64-encoded instructions to PowerShell, bypassing basic command-line monitoring that looks for plaintext keywords. This is one of the most common execution techniques observed in real-world intrusions.

## Containment (Production Response)

In a production environment, the following actions would be taken:

1. **Isolate the endpoint** — Remove from network to prevent lateral movement
2. **Decode the payload** — `echo [Base64] | base64 -d` to determine what was executed
3. **Check for persistence** — Examine registry Run keys, scheduled tasks, and startup folders
4. **Review related alerts** — Search for other alerts from the same agent within the same time window
5. **Escalate if needed** — If payload is confirmed malicious, escalate to Tier 2 / Incident Response team

## Lessons Learned

- Detection latency was under 5 seconds from execution to alert — acceptable for real-time monitoring
- The `-EncodedCommand` pattern is a reliable detection signal with low false-positive rate in most environments
- Sysmon's full command-line logging (enabled by the Olaf Hartong modular config) was essential — without it, only the process name would be visible
- Initial Atomic Red Team Test 1 for T1059.001 used `IEX DownloadString` instead of `-EncodedCommand` — this revealed that a single MITRE technique can have multiple execution methods requiring separate rules

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Execution |
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Data Source | Process: Process Creation (Sysmon Event ID 1) |
| Detection Method | Command-line regex matching `-EncodedCommand` parameter |
