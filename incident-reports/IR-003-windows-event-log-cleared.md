# Incident Report IR-003 — Windows Event Log Cleared

## Executive Summary

A Windows System event log was cleared on the Windows 11 SOC endpoint (192.168.56.103) on April 5, 2026. Event log clearing is a defence evasion technique used by attackers to destroy forensic evidence of their activity. Custom Wazuh Rule 100006 fired within 3 seconds, generating a Level 14 (Critical) alert mapped to MITRE ATT&CK technique T1070.001. Critically, the log-clearing event itself was captured in the Wazuh Elasticsearch index before the local log was deleted — demonstrating that centralised SIEM forwarding preserves evidence an attacker cannot destroy from the endpoint.

## Classification

| Field | Value |
|---|---|
| **Report ID** | IR-003 |
| **Date** | April 5, 2026 |
| **Severity** | Critical (Level 14) |
| **MITRE ATT&CK** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Rule Triggered** | 100006 |
| **Agent** | WIN11-SOC-Endpoint (Agent 001) |
| **Agent IP** | 192.168.56.103 |
| **Status** | Closed — Simulated attack (Atomic Red Team) |

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-05 10:35:00 | Atomic Red Team T1070.001 test initiated |
| 2026-04-05 10:35:01 | `wevtutil cl System` executed — System event log cleared |
| 2026-04-05 10:35:01 | Windows generates Event ID 104 (Log Cleared) before log is wiped |
| 2026-04-05 10:35:01 | Wazuh Agent 001 captures and forwards the event |
| 2026-04-05 10:35:02 | Event arrives at Wazuh Manager and is indexed in Elasticsearch |
| 2026-04-05 10:35:03 | Rule 100006 (chained off built-in 60106) fires — Critical alert |
| 2026-04-05 10:35:03 | Local System log is now empty — but alert is preserved in SIEM |

## Evidence

| Field | Value |
|---|---|
| `rule.id` | 100006 |
| `rule.level` | 14 |
| `rule.description` | CRITICAL: Windows event log cleared — anti-forensics activity (T1070.001) |
| `agent.name` | WIN11-SOC-Endpoint |
| `agent.id` | 001 |
| `agent.ip` | 192.168.56.103 |
| `data.win.system.eventID` | 104 |
| `data.win.system.channel` | System |
| `data.win.eventdata.channel` | System |
| `data.win.system.computer` | WIN11-SOC-Endpoint |
| `data.win.eventdata.user` | WIN11-SOC-Endpoint\Jackal |

## Investigation

**Step 1 — Alert triage:** Rule 100006 fired at Level 14 (Critical) — the highest severity in the custom rule set. Log clearing is almost never legitimate in a monitored environment and indicates either an active attacker or a seriously misconfigured maintenance process.

**Step 2 — User context:** The clearing was performed by `WIN11-SOC-Endpoint\Jackal`. In production, immediately verify whether this user had an authorised reason to clear logs (they almost certainly did not).

**Step 3 — Temporal correlation:** Search for ALL alerts from Agent 001 in the 30 minutes preceding the log clearing. Attackers clear logs after completing their objectives — the preceding activity is likely the actual attack. Any alerts that were triggered before the clear would still be preserved in Wazuh's Elasticsearch index.

**Step 4 — Method analysis:** `wevtutil cl System` is a command-line utility. Check for clearing of other log channels — attackers who clear one log typically attempt to clear Security, Application, and Sysmon logs as well.

**Step 5 — SIEM integrity verification:** Confirm that the Wazuh Elasticsearch index contains all events from the endpoint up to and including the clearing event. This validates that centralised log forwarding captured everything before local destruction.

## Root Cause

MITRE ATT&CK Technique **T1070.001 — Indicator Removal on Host: Clear Windows Event Logs**. Attackers clear event logs to remove evidence of their activity — login attempts, process execution, registry modifications, and network connections would all be lost if only stored locally. This technique is used in the late stages of an attack after the attacker has achieved their objectives.

## Containment (Production Response)

1. **Immediately isolate the endpoint** — Log clearing is a high-confidence indicator of active compromise
2. **Preserve SIEM evidence** — Export all indexed events from this agent for the past 24–72 hours
3. **Check other log channels** — Verify Security, Application, PowerShell, and Sysmon logs for clearing attempts
4. **Full timeline reconstruction** — Use the preserved SIEM data to build a complete timeline of attacker activity
5. **Memory acquisition** — If possible, capture a memory dump before the attacker can terminate their tools
6. **Credential reset** — Reset the compromised user's credentials and any accounts that were active on the endpoint
7. **Escalate to IR team** — Log clearing at Level 14 warrants full incident response engagement

## Key Finding — Centralised Log Forwarding

This simulation demonstrated a fundamental SIEM architecture principle:

**The local Windows System log was successfully cleared** — `wevtutil cl System` emptied the log on the endpoint. An investigator examining only the local machine would find an empty log with no evidence.

**But the clearing event itself was already captured in Wazuh** — because the Wazuh agent forwards events to the Manager in near-real-time, the log-clearing event (Windows Event ID 104) was indexed in Elasticsearch before the local log was wiped. All events that existed in the log before clearing were also already forwarded and preserved.

This is why centralised SIEM monitoring exists — it creates a forensic record that an attacker cannot destroy from the endpoint alone. They would need to compromise the SIEM infrastructure itself, which is a significantly harder target.

## Lessons Learned

- Rule 100006 chains off Wazuh built-in rule `60106` using `if_sid` — this is more reliable than writing a standalone rule because the built-in rule has already validated the event structure
- Level 14 (Critical) is appropriate — there is almost no legitimate reason to clear event logs in a monitored environment
- The 3-second detection latency demonstrates that centralised forwarding outpaces local log destruction
- In production, log clearing should trigger automated response actions (endpoint isolation, ticket creation) via SOAR integration
- Monitoring for Event ID 1102 (Security log cleared) should also be considered alongside Event ID 104 (System/Application log cleared)

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Defence Evasion |
| Technique | T1070.001 — Indicator Removal on Host: Clear Windows Event Logs |
| Data Source | Command: Command Execution / Windows Event Log: Log Cleared |
| Detection Method | Chained off Wazuh built-in rule 60106 (Windows Event ID 104) |
