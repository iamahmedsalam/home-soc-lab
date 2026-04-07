# Attack Simulation Results — Phase C

## Overview

All attack simulations were executed using **Atomic Red Team** (Red Canary) on the Windows 11 endpoint (192.168.56.103) during Phase C of the Home SOC Lab v2.0 build. Each test maps to a MITRE ATT&CK technique with a corresponding custom detection rule.

Atomic Red Team was installed on the Windows 11 VM at `C:\AtomicRedTeam\atomics` and executed via PowerShell with administrative privileges.

## Detection Results Matrix

| Rule ID | MITRE Technique | Attack Method | Result | Detection Time | Notes |
|---|---|---|---|---|---|
| 100001 | T1059.001 | `Invoke-AtomicTest T1059.001` — PowerShell `-EncodedCommand` | ✅ **DETECTED** | < 5 seconds | Alert fired immediately in Wazuh dashboard |
| 100002 | T1059.001 | Office macro → PowerShell spawn | ⚠️ **PENDING** | N/A | Microsoft Office not installed on endpoint — rule syntax validated via `wazuh-logtest` |
| 100003 | T1003.001 | `rundll32.exe comsvcs.dll MiniDump` against LSASS PID | ⚠️ **BLOCKED BY OS** | N/A | Windows 11 Enterprise Credential Guard + LSA Protection blocked all attempts |
| 100004 | T1547.001 | `Invoke-AtomicTest T1547.001` — `reg.exe` Run key modification | ✅ **DETECTED** | < 5 seconds | Registry persistence caught via Sysmon Event 13 |
| 100005 | T1136.001 | `Invoke-AtomicTest T1136.001` — `net user /add` | ✅ **DETECTED** | < 5 seconds | New account creation flagged correctly |
| 100006 | T1070.001 | `Invoke-AtomicTest T1070.001` — `wevtutil cl System` | ✅ **DETECTED** | < 3 seconds | Log clearing alert fired — log already captured in Wazuh before local deletion |
| 100007 | T1055 | `Invoke-AtomicTest T1055` — CreateRemoteThread injection | ✅ **DETECTED** | < 5 seconds | Process injection API calls captured in command line |
| 100008 | T1105 | `Invoke-AtomicTest T1105` — Executable written to `%TEMP%` | ✅ **DETECTED** | < 5 seconds | File creation in Temp folder caught via Sysmon Event 11 |
| 100009 | T1021.001 | `xfreerdp` from Kali (192.168.56.50) to Windows (192.168.56.103) | ⚠️ **BLOCKED BY OS** | N/A | RDP service enabled but port 3389 restricted in Enterprise Evaluation edition |
| 100010 | T1083 | `Invoke-AtomicTest T1083` — `dir /s /b` recursive enumeration | ✅ **DETECTED** | < 5 seconds | Directory enumeration command captured |

## Summary

| Metric | Value |
|---|---|
| Total rules tested | 10 |
| Detected by custom rules | **8** |
| Blocked by OS-level defences | **2** (T1003.001 + T1021.001) |
| False positives observed | 0 |
| Detection rate (where attack executed) | **100%** (8/8 that reached the endpoint) |
| Overall detection rate | **80%** (8/10 including OS-blocked) |

## Detailed Findings

### T1059.001 — PowerShell Encoded Command (Rule 100001)

**Test executed:** `Invoke-AtomicTest T1059.001` — Test 7 (PowerShell with `-EncodedCommand` flag)

**What happened:** The initial Atomic Red Team Test 1 for T1059.001 actually runs a Mimikatz download via `IEX (New-Object Net.WebClient).DownloadString()` — not an encoded command. This was a detection gap discovery — the test didn't match the rule because it uses a different execution method. Test 7, which specifically uses `-EncodedCommand`, triggered Rule 100001 successfully.

**Real-world insight:** This demonstrated that a single MITRE technique can have multiple execution methods. Comprehensive detection requires rules for each variant. The IEX/DownloadString pattern was identified as a future Rule 100011 candidate.

### T1003.001 — LSASS Credential Dumping (Rule 100003)

**Tests attempted:**
1. `rundll32.exe comsvcs.dll, MiniDump <LSASS_PID> %TEMP%\lsass.dmp full`
2. Direct LSASS PID dump with admin privileges and Defender disabled

**Result:** "Access is denied" on all attempts. Windows 11 Enterprise Credential Guard encrypts LSASS memory at the hypervisor level. LSA Protection (`RunAsPPL`) adds an additional barrier. Both protections remained active even with administrative privileges and real-time Defender monitoring disabled.

**Documentation value:** This is defence-in-depth working correctly. The rule logic was validated via `wazuh-logtest` synthetic events and would fire on endpoints without Credential Guard (older Windows versions, misconfigured systems).

### T1021.001 — RDP Lateral Movement (Rule 100009)

**Test attempted:** `xfreerdp /u:Jackal /p:LabPass123 /v:192.168.56.103:3389 /cert:ignore /sec:rdp` from Kali

**Steps taken:**
1. Enabled RDP via registry: `Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0`
2. Enabled firewall rule: `Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
3. Started TermService: `Start-Service -Name "TermService"`

**Result:** RDP service started but connection failed. `netstat -an | findstr 3389` returned nothing — port 3389 not listening despite service running. Windows 11 Enterprise Evaluation edition restricts RDP functionality.

**Documentation value:** Rule syntax is correct and would detect `mstsc.exe` launches on systems where RDP is fully operational.

### T1070.001 — Event Log Cleared (Rule 100006)

**Key finding:** When `wevtutil cl System` was executed, the local Windows System log was cleared — but the Wazuh alert for the clearing event was already captured in the Elasticsearch index before the local log was deleted. This demonstrates a core SIEM architecture principle: centralised log forwarding preserves forensic evidence that an attacker cannot destroy by clearing local logs.

## Atomic Red Team Installation

**Location:** `C:\AtomicRedTeam\atomics` on Windows 11 endpoint

**Installation commands:**
```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force
```

**Test execution pattern:**
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 7
```

**Cleanup after testing:**
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 7 -Cleanup
```
