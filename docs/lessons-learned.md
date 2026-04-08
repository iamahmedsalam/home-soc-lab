# Lessons Learned — Home SOC Lab v2.0

## Overview

This document captures the key technical findings, unexpected discoveries, and real-world insights gained across all five phases of the Home SOC Lab v2.0 build. These are the observations that would be most relevant in a SOC analyst interview or technical discussion.

---

## Detection Engineering

### Wazuh 4.14.4 Group Naming Convention

**Discovery:** Wazuh v4.14.4 uses `sysmon_eid1_detections`, `sysmon_eid10_detections`, `sysmon_eid11_detections`, and `sysmon_eid13_detections` as Sysmon group names — not the `sysmon_event1` format found in most online tutorials and older documentation.

**Impact:** All 10 custom rules were initially written with the old naming format and failed silently — no errors, no alerts, just no detections. The rules were syntactically valid but never triggered because the `if_group` value didn't match any existing group.

**Fix:** All rules updated via `sed` command to replace old group names with the correct v4.14.4 format.

**Takeaway:** Always verify group names against the actual installed version's rule files (`/var/ossec/ruleset/rules/`) rather than relying on external documentation. Version-specific differences are a common source of silent failures in SIEM deployments.

### if_sid vs if_group — When to Use Each

**Finding:** `if_sid` chaining (referencing a specific parent rule ID) is more reliable than `if_group` when building on top of existing Wazuh built-in detections. `if_group` is better when matching against raw Sysmon event categories where no built-in rule covers the specific detection logic needed.

**Example:** Rule 100006 (log clearing) chains off built-in rule `60106` using `if_sid`. This works reliably because rule 60106 has already validated the event structure. Rules 100001–100005 use `if_group` because they match against Sysmon event categories directly with custom field regex.

### PCRE2 Case-Insensitive Flag

**Practice:** Every regex pattern uses `(?i)` for case-insensitive matching. This prevents attackers from evading detection through case variation — one of the simplest evasion techniques (`powershell.exe` vs `PoWeRsHeLl.ExE`).

### Pre-Deployment Validation

**Workflow:** `xmllint --noout` was run before every rule deployment to validate XML syntax. This single step prevents pushing broken configuration to a live SIEM, which would cause monitoring gaps. In production environments, this would be part of a CI/CD pipeline for detection-as-code.

---

## Windows 11 Enterprise Hardening

### Credential Guard Blocking LSASS Dumps

**Observation:** Windows 11 Enterprise Credential Guard blocked all LSASS memory dump attempts — including `rundll32.exe comsvcs.dll MiniDump`, direct PID dumps, and attempts with admin privileges and Defender disabled.

**Root cause:** Credential Guard uses virtualisation-based security (VBS) to isolate LSASS in a protected container. The credentials are encrypted at the hypervisor level and inaccessible to processes running in the standard Windows user mode — even those running as SYSTEM.

**Significance:** This is defence-in-depth working correctly. Attackers targeting modern Windows 11 Enterprise endpoints face the same barriers. Rule 100003 would fire on older Windows versions or systems where Credential Guard is not enabled, which remain common in enterprise environments.

### RDP Restrictions in Enterprise Evaluation

**Observation:** RDP service (`TermService`) started successfully and registry settings were configured, but port 3389 did not bind to a listening state. `netstat -an | findstr 3389` returned no results despite the service showing as running.

**Root cause:** Windows 11 Enterprise Evaluation edition restricts certain remote access functionality. In a full-licensed Enterprise deployment, RDP works normally.

**Significance:** Rule 100009 syntax was validated and would detect `mstsc.exe` launches on systems with functional RDP.

---

## SIEM Architecture

### Centralised Forwarding Preserves Evidence

**Demonstration:** During the T1070.001 (log clearing) simulation, `wevtutil cl System` successfully deleted the local System log. However, the Wazuh alert for the clearing event was already indexed in Elasticsearch before the local log was wiped.

**Principle:** This is the fundamental value proposition of centralised SIEM monitoring. An attacker who gains access to an endpoint can destroy local logs, but they cannot retroactively remove events that have already been forwarded to and indexed by the SIEM. To destroy SIEM evidence, they would need to compromise the SIEM infrastructure itself.

### Host-Only Networking for Lab Stability

**Decision:** All VMs use VirtualBox Host-Only adapters (192.168.56.0/24) instead of Bridged networking for lab communication.

**Reason:** Bridged networking assigns IPs from the router's DHCP pool, which change when the host machine connects to different WiFi networks. This would break agent-to-manager connectivity after every location change. Host-Only addresses are managed by VirtualBox and remain static regardless of external network conditions.

**Dual-adapter design:** A second NAT adapter on each VM provides internet access for updates and tool downloads without exposing lab traffic externally.

### Change Management Awareness

**Observation documented:** When 29 pending updates were applied to the Wazuh Manager VM, the following note was made for documentation: "In a production environment, this would be scheduled during a change management window to minimise monitoring gaps."

**Significance:** This demonstrates awareness of operational SOC practices beyond pure technical skills. SIEM updates in production require coordination to avoid gaps in monitoring coverage.

---

## Attack Simulation Insights

### Single MITRE Technique, Multiple Execution Methods

**Discovery:** Atomic Red Team Test 1 for T1059.001 (PowerShell) actually runs a Mimikatz download via `IEX (New-Object Net.WebClient).DownloadString()` — not an encoded command. Rule 100001 targets `-EncodedCommand` specifically.

**Lesson:** A single MITRE technique ID can encompass dozens of distinct execution methods. Comprehensive detection requires multiple rules per technique, each targeting a different variant. The IEX/DownloadString pattern was identified as a candidate for a future Rule 100011.

### 80% Detection Rate with Documentation

**Result:** 8 out of 10 rules fired successfully during live testing. The 2 that didn't fire (T1003.001 LSASS dump and T1021.001 RDP) were blocked by OS-level defences — not detection failures.

**Documentation approach:** Rather than reporting "80% detection rate" as a limitation, both blocked techniques were documented as positive security findings demonstrating defence-in-depth. This is the correct analytical framing — a SOC analyst should recognise when defensive controls are working as intended.

### Network Reconnaissance Observations

**Nmap finding:** Scanning the Windows 11 endpoint from Kali showed "host is up" with 0.39ms latency but "1000 filtered tcp ports" — Windows Firewall silently drops packets rather than sending RST responses. The MAC address was visible, confirming Layer 2 connectivity on the same network segment.

**Significance:** This is a real-world observation worth including in documentation. It shows analytical capability — understanding what filtered ports mean versus closed ports, and recognising that host reachability at Layer 2 doesn't require ICMP responses.

---

## Process and Methodology

### Troubleshooting as a Skill

**Placeholder error:** During initial setup, `NEW_WAZUH_IP` was accidentally left as a literal string in the Windows agent configuration instead of being replaced with `192.168.56.101`. The agent attempted to connect to a non-existent address.

**Connection name error:** The Kali `nmcli` command referenced `"SOC-Lab"` as the connection name, but the actual NetworkManager connection was named `"Wired connection 1"`. The fix required `nmcli connection show` to verify the real name first.

**Takeaway:** Both errors were diagnosed and fixed independently. In real SOC/sysadmin work, the ability to troubleshoot configuration issues is as important as the ability to follow instructions. Environment-specific values must always be verified before running commands.

### Screenshot-First Documentation

**Practice:** Every phase was documented with screenshots saved in a consistent naming convention (`A1-sysmon-config.png`, `B-all-10-rules-verified.png`, `C-T1059-alert-fired.png`). This creates a visual evidence trail that supports the written documentation.

**Value:** Screenshots prove work was done on real systems — not copied from tutorials. A recruiter can see actual Wazuh dashboard alerts, actual terminal output, and actual detection results.
