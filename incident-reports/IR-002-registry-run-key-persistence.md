# Incident Report IR-002 — Registry Run Key Persistence

## Executive Summary

A modification to a Windows Registry Run key was detected on the Windows 11 SOC endpoint (192.168.56.103) on April 5, 2026. Registry Run keys specify programs that execute automatically at user login, making them a primary persistence mechanism used by attackers to survive system reboots. Custom Wazuh Rule 100004 fired within 5 seconds, generating a Level 10 (High) alert mapped to MITRE ATT&CK technique T1547.001.

## Classification

| Field | Value |
|---|---|
| **Report ID** | IR-002 |
| **Date** | April 5, 2026 |
| **Severity** | High (Level 10) |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Rule Triggered** | 100004 |
| **Agent** | WIN11-SOC-Endpoint (Agent 001) |
| **Agent IP** | 192.168.56.103 |
| **Status** | Closed — Simulated attack (Atomic Red Team) |

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-05 10:12:00 | Atomic Red Team T1547.001 test initiated |
| 2026-04-05 10:12:01 | `reg.exe` executed to add value to `HKLM\...\Run` key |
| 2026-04-05 10:12:01 | Sysmon Event ID 13 (Registry Value Set) logged |
| 2026-04-05 10:12:02 | Wazuh Agent 001 forwarded event to Manager |
| 2026-04-05 10:12:03 | Rule 100004 matched — alert generated |
| 2026-04-05 10:12:05 | Alert visible in dashboard with T1547.001 mapping |

## Evidence

| Field | Value |
|---|---|
| `rule.id` | 100004 |
| `rule.level` | 10 |
| `rule.description` | Registry Run key modification detected — possible persistence (T1547.001) |
| `agent.name` | WIN11-SOC-Endpoint |
| `agent.id` | 001 |
| `agent.ip` | 192.168.56.103 |
| `data.win.system.eventID` | 13 |
| `data.win.system.channel` | Microsoft-Windows-Sysmon/Operational |
| `data.win.eventdata.eventType` | SetValue |
| `data.win.eventdata.targetObject` | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\[test value] |
| `data.win.eventdata.image` | C:\Windows\System32\reg.exe |
| `data.win.eventdata.user` | WIN11-SOC-Endpoint\Jackal |

## Investigation

**Step 1 — Alert triage:** Alert `rule.id: 100004` appeared in the Wazuh dashboard. Level 10 (High) — registry persistence modifications always warrant investigation.

**Step 2 — Registry path analysis:** The `targetObject` field shows a value being set under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`. This key is one of the most commonly abused persistence locations in Windows — any value added here will execute the specified program at every user login.

**Step 3 — Source process:** The modifying process was `reg.exe` — the legitimate Windows registry editor. Attackers frequently use built-in system tools (living-off-the-land) to avoid triggering alerts that look for custom malware executables.

**Step 4 — Value analysis:** In production, the value data would be examined to determine what executable was being set to auto-run. Cross-reference with known-good software inventory to determine if the entry is legitimate (e.g., antivirus, VPN client) or suspicious.

**Step 5 — Scope check:** Search for other registry modifications from the same user/process within the same time window. Attackers often set multiple persistence mechanisms simultaneously.

## Root Cause

MITRE ATT&CK Technique **T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**. This technique ensures malicious code survives system reboots by registering it in a location that Windows automatically executes during the login process. It is one of the most prevalent persistence techniques observed across all threat actor groups.

## Containment (Production Response)

1. **Examine the Run key value** — Determine what executable path was added
2. **Check if the executable exists** — Verify the file on disk, get its hash
3. **Hash lookup** — Submit to VirusTotal or internal threat intel platform
4. **Remove the registry entry** — `reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v [value_name] /f`
5. **Delete the payload** — If the executable is confirmed malicious, quarantine or delete it
6. **Scan for additional persistence** — Check `RunOnce`, `Startup` folder, scheduled tasks, services
7. **Monitor for re-creation** — The attacker may have a secondary persistence mechanism that recreates the Run key

## Lessons Learned

- Sysmon Event 13 (Registry Value Set) provides the exact registry path and the process that made the modification — critical for determining legitimacy
- The `Run` and `RunOnce` keys exist in both `HKLM` (all users) and `HKCU` (current user) — both must be monitored. The rule's regex `\\(Run|RunOnce)\\` catches both locations
- Living-off-the-land techniques (using `reg.exe`) make it impossible to detect persistence by process name alone — the registry path and value data must be analysed
- This is one of the highest-confidence detections in the rule set — legitimate Run key modifications are relatively rare in day-to-day operations

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Persistence |
| Technique | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| Data Source | Windows Registry: Windows Registry Key Modification (Sysmon Event ID 13) |
| Detection Method | Registry path regex matching `\Run\` or `\RunOnce\` in `targetObject` |
