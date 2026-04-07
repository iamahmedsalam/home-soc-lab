# Detection Rules — Engineering Reference

## Overview

10 custom Wazuh detection rules written from scratch, each mapped to a specific MITRE ATT&CK technique. Rules are stored in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager — this file is reserved for custom rules and survives Wazuh updates.

## Rule Anatomy

Every Wazuh rule follows this structure:

```xml
<rule id="100001" level="10">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)regex_pattern</field>
    <description>Human-readable alert description (MITRE ID)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>tags,for,filtering,</group>
</rule>
```

**Key components:**
- `id` — Unique rule ID. Custom rules use 100000+ to avoid conflicts with Wazuh built-in rules
- `level` — Severity (0–15). Determines alert priority in the dashboard
- `if_group` / `if_sid` — Parent condition. Determines which log events this rule evaluates
- `field` — Regex match against a specific log field. Uses PCRE2 syntax
- `mitre` — Maps the rule to a MITRE ATT&CK technique ID
- `group` — Tags for filtering and categorisation in dashboards

## Chaining Strategy: `if_group` vs `if_sid`

Two approaches were used depending on the rule:

**`if_group`** — Targets a category of Sysmon events by group name. Used for Rules 100001–100005, 100007–100010 where we match against raw Sysmon event types.

**`if_sid`** — Targets a specific Wazuh built-in rule by ID. Used for Rule 100006 (chains off built-in rule `60106` for Windows log cleared). More reliable when building on top of existing Wazuh detections because the parent rule has already validated the event structure.

**Lesson learned:** `if_sid` chaining is more predictable when an existing Wazuh rule already handles the event type. `if_group` is better when writing rules against raw Sysmon data where no built-in rule covers the specific detection logic needed.

## Wazuh 4.14.4 Group Naming

**Critical discovery during this build:** Wazuh 4.14.4 uses updated Sysmon group names that differ from older documentation and tutorials:

| Sysmon Event | Wazuh 4.14.4 Group Name | Old Format (pre-4.x) |
|---|---|---|
| Event 1 — Process Creation | `sysmon_eid1_detections` | `sysmon_event1` |
| Event 10 — Process Access | `sysmon_eid10_detections` | `sysmon_event_10` |
| Event 11 — File Created | `sysmon_eid11_detections` | `sysmon_event_11` |
| Event 13 — Registry Value Set | `sysmon_eid13_detections` | `sysmon_event_13` |

All 10 rules were updated via `sed` to use the correct naming after this was discovered during rule validation. This is a common pitfall when following older Wazuh tutorials.

## PCRE2 Regex — Evasion Resistance

Every regex uses the `(?i)` case-insensitive flag. Without it, an attacker could bypass detection by changing case:

```
powershell.exe -EncodedCommand ...    ← Detected
POWERSHELL.EXE -encodedcommand ...    ← Also detected (with (?i))
PoWeRsHeLl.ExE -eNcOdEdCoMmAnD ...   ← Also detected (with (?i))
```

This is a real-world evasion technique — case variation is one of the simplest ways attackers attempt to bypass string-matching rules.

## Sysmon Event ID Coverage

| Event ID | What It Logs | Rules Using It |
|---|---|---|
| Event 1 | Process creation (new processes with full command line) | 100001, 100002, 100005, 100007, 100009, 100010 |
| Event 10 | Process access (one process accessing another's memory) | 100003 |
| Event 11 | File creation (new files written to disk) | 100008 |
| Event 13 | Registry value set (registry modifications) | 100004 |

Spreading rules across multiple Sysmon event types provides coverage across the full attack lifecycle — not just process execution.

## Severity Level Design

| Level | Classification | Rules | Rationale |
|---|---|---|---|
| 14 — Critical | Immediate action required | 100003, 100006 | Credential theft and anti-forensics — highest impact |
| 13 — Critical | High-confidence malicious activity | 100002 | Office spawning PowerShell is almost always malicious |
| 12 — High | Strong indicator of compromise | 100007 | Process injection APIs in command line |
| 10 — High | Suspicious activity requiring investigation | 100001, 100004, 100005, 100008 | Common attack techniques that may have legitimate uses |
| 8 — Medium | Notable activity | 100009 | RDP usage can be legitimate — needs context |
| 7 — Medium | Low-confidence indicator | 100010 | Directory enumeration is common in normal admin work |

Severity levels directly impact alert prioritisation in the SOC dashboard. Properly calibrated levels reduce alert fatigue — the most common operational problem in real SOC environments.

## Rule-by-Rule Breakdown

### Rule 100001 — PowerShell Encoded Command (T1059.001)
**What it detects:** PowerShell launched with the `-EncodedCommand` parameter, which accepts Base64-encoded commands. Attackers use this to obfuscate malicious commands and bypass basic string-matching defences.

**Sysmon source:** Event 1 (Process Creation) — `commandLine` field

### Rule 100002 — Office Spawns PowerShell (T1059.001)
**What it detects:** Microsoft Office applications (Word, Excel, PowerPoint, Outlook) spawning PowerShell as a child process. This is the classic macro-based attack chain — a user opens a malicious document, the macro executes, and PowerShell runs the payload.

**Sysmon source:** Event 1 — `parentImage` and `image` fields

### Rule 100003 — LSASS Credential Dumping (T1003.001)
**What it detects:** Any process accessing `lsass.exe` memory. LSASS (Local Security Authority Subsystem Service) stores credential hashes in memory — tools like Mimikatz read this memory to extract passwords.

**Sysmon source:** Event 10 (Process Access) — `targetImage` field

### Rule 100004 — Registry Run Key Persistence (T1547.001)
**What it detects:** Modifications to `Run` or `RunOnce` registry keys. These keys specify programs that execute automatically at user login — a common persistence mechanism.

**Sysmon source:** Event 13 (Registry Value Set) — `targetObject` field

### Rule 100005 — New Local Account Created (T1136.001)
**What it detects:** `net user /add` or `net localgroup administrators /add` commands. Attackers create local accounts to maintain access after initial compromise.

**Sysmon source:** Event 1 — `commandLine` field

### Rule 100006 — Windows Event Log Cleared (T1070.001)
**What it detects:** Windows event logs being cleared via `wevtutil` or Event Viewer. Attackers clear logs to remove evidence of their activity.

**Chains off:** Wazuh built-in rule `60106` (using `if_sid`)

### Rule 100007 — Process Injection (T1055)
**What it detects:** Windows API calls associated with process injection (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`) appearing in command-line arguments.

**Sysmon source:** Event 1 — `commandLine` field

### Rule 100008 — Executable in Temp Folder (T1105)
**What it detects:** Executable files (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.cmd`) created in Temp directories. Malware droppers commonly write payloads to Temp before execution.

**Sysmon source:** Event 11 (File Created) — `targetFilename` field

### Rule 100009 — RDP Lateral Movement (T1021.001)
**What it detects:** The RDP client (`mstsc.exe`) being launched, which may indicate lateral movement to another system via Remote Desktop.

**Sysmon source:** Event 1 — `image` field

### Rule 100010 — Directory Enumeration (T1083)
**What it detects:** Recursive directory listing commands (`dir /s`, `tree /f`, `Get-ChildItem -Recurse`). Attackers enumerate file systems during the discovery phase to locate sensitive data.

**Sysmon source:** Event 1 — `commandLine` field

## Validation Workflow

Every rule was validated before deployment using this process:

1. **XML syntax check** — `sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml` (must return no output = no errors)
2. **Restart Wazuh Manager** — `sudo systemctl restart wazuh-manager`
3. **Verify rule loaded** — `sudo /var/ossec/bin/wazuh-logtest` with synthetic test events
4. **Live validation** — Atomic Red Team attack simulation to generate real alerts (Phase C)

Pre-change validation with `xmllint` prevents pushing broken XML to a live SIEM — a small step that avoids monitoring gaps in production environments.
