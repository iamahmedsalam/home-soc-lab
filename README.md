# 🛡️ Home SOC Lab v2.0

**A production-grade Security Operations Center home lab featuring multi-platform endpoint monitoring, custom MITRE ATT&CK-mapped detection engineering, adversary simulation, and professional incident response documentation.**

> Built by [Ahmed Salam](https://iamahmedsalam.com) — Aspiring AI-Augmented SOC Analyst | CompTIA Security+ | TryHackMe Top 2%

---

## 📋 Project Overview

This lab demonstrates end-to-end SOC analyst capabilities across five phases — from infrastructure deployment through detection engineering, attack simulation, dashboard creation, and incident response documentation. Every detection rule was written, tested, and validated against real attack simulations.

| | |
|---|---|
| **SIEM Platform** | Wazuh 4.14.4 |
| **Endpoints Monitored** | Windows 11 Enterprise + Ubuntu 24.04 LTS |
| **Attack Platform** | Kali Linux |
| **Detection Rules** | 10 custom rules mapped to MITRE ATT&CK |
| **Attack Simulations** | Atomic Red Team — 8/10 techniques detected |
| **Incident Reports** | 3 professional IR documents |
| **Framework** | MITRE ATT&CK v14 |

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│              VirtualBox Host-Only Network            │
│                  192.168.56.0/24                     │
│                                                     │
│  ┌─────────────┐    ┌──────────────────────────┐    │
│  │ Kali Linux  │    │     Wazuh Manager        │    │
│  │192.168.56.50│────│     Ubuntu 24.04 LTS     │    │
│  │  Attack VM  │    │     192.168.56.101       │    │
│  └─────────────┘    │     Wazuh 4.14.4         │    │
│                     └──────────┬───────────────┘    │
│                                │                    │
│                 ┌──────────────┴──────────────┐     │
│                 │                             │     │
│  ┌──────────────┴─────────┐  ┌───────────────┴──┐  │
│  │     Windows 11         │  │ Ubuntu 24.04 LTS │  │
│  │     192.168.56.103     │  │ 192.168.56.104   │  │
│  │     Wazuh Agent 001    │  │ Wazuh Agent 002  │  │
│  │     Sysmon v15.15      │  │ auditd           │  │
│  └────────────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**All VMs use dual adapters:**
- Adapter 1: Host-Only (192.168.56.0/24) — lab communication
- Adapter 2: NAT — internet access for updates and tools

---

## 📁 Repository Structure

```
home-soc-lab/
├── README.md
├── lab-architecture/
│   └── network-diagram.md          # Full network topology & VM specs
├── detection-rules/
│   ├── local_rules.xml             # All 10 custom Wazuh rules
│   └── rules-reference.md          # Rule breakdown & engineering notes
├── attack-simulations/
│   └── simulation-results.md       # Full detection matrix & findings
├── incident-reports/
│   ├── IR-001-powershell-encoded-command.md
│   ├── IR-002-registry-run-key-persistence.md
│   └── IR-003-windows-event-log-cleared.md
├── screenshots/
│   ├── phase-a/                    # Lab setup & agent deployment
│   ├── phase-b/                    # Detection rule creation
│   ├── phase-c/                    # Attack simulations & alerts
│   └── phase-d/                    # Custom dashboards
└── docs/
    └── lessons-learned.md          # Key technical findings
```

---

## 🔍 Detection Rules — MITRE ATT&CK Coverage

10 custom rules written from scratch, validated against live attack simulations:

| Rule ID | Technique | Description | Level |
|---|---|---|---|
| 100001 | T1059.001 | PowerShell encoded command execution | 10 — High |
| 100002 | T1059.001 | Office application spawns PowerShell | 13 — Critical |
| 100003 | T1003.001 | LSASS memory access — credential dumping | 14 — Critical |
| 100004 | T1547.001 | Registry Run key persistence | 10 — High |
| 100005 | T1136.001 | New local user account created | 10 — High |
| 100006 | T1070.001 | Windows event log cleared | 14 — Critical |
| 100007 | T1055 | Process injection indicators | 12 — High |
| 100008 | T1105 | Executable dropped in Temp folder | 10 — High |
| 100009 | T1021.001 | RDP lateral movement | 8 — Medium |
| 100010 | T1083 | Suspicious directory enumeration | 7 — Medium |

---

## ⚔️ Attack Simulation Results

Real attack simulations executed using Atomic Red Team against the Windows 11 endpoint:

| Technique | Method | Result | Rule |
|---|---|---|---|
| T1059.001 | PowerShell -EncodedCommand | ✅ DETECTED | 100001 |
| T1059.001 | Office macro → PowerShell | ⚠️ Pending (no Office) | 100002 |
| T1003.001 | LSASS dump via comsvcs.dll | ⚠️ Blocked by Credential Guard | 100003 |
| T1547.001 | reg.exe Run key modification | ✅ DETECTED | 100004 |
| T1136.001 | net user /add | ✅ DETECTED | 100005 |
| T1070.001 | wevtutil cl System | ✅ DETECTED | 100006 |
| T1055 | CreateRemoteThread injection | ✅ DETECTED | 100007 |
| T1105 | Executable dropped in %TEMP% | ✅ DETECTED | 100008 |
| T1021.001 | RDP from Kali Linux | ⚠️ Blocked by Win11 Enterprise | 100009 |
| T1083 | dir /s /b directory enumeration | ✅ DETECTED | 100010 |

**Detection Rate: 8/10 (80%)** — 2 blocked by Windows 11 Enterprise hardening (documented as positive security findings)

---

## 📋 Incident Reports

Three professional incident reports written from real alert data:

| Report | Technique | Severity | Rule |
|---|---|---|---|
| [IR-001](incident-reports/IR-001-powershell-encoded-command.md) | T1059.001 — PowerShell Encoded Command | High (Level 10) | 100001 |
| [IR-002](incident-reports/IR-002-registry-run-key-persistence.md) | T1547.001 — Registry Persistence | High (Level 10) | 100004 |
| [IR-003](incident-reports/IR-003-windows-event-log-cleared.md) | T1070.001 — Event Log Cleared | Critical (Level 14) | 100006 |

Each report includes: Executive Summary, Timeline, Evidence, Investigation, Root Cause, Containment, Lessons Learned, MITRE ATT&CK Mapping, and full Artifacts table with exact forensic values from real Wazuh alerts.

---

## 🔑 Key Technical Findings

**Detection Engineering:**
- Wazuh v4.14.4 uses `sysmon_eid1_detections` group naming (not `sysmon_event1`) — discovered and corrected during rule validation
- `if_sid` chaining is more reliable than `if_group` for rules building on existing Wazuh built-in detections
- PCRE2 regex with `(?i)` case-insensitive flag prevents attacker evasion via case variation

**Windows 11 Enterprise Hardening Observed:**
- Credential Guard + LSA Protection blocked all LSASS dump attempts even with admin rights and Defender disabled
- RDP service binds successfully but port 3389 restricted in Enterprise Evaluation edition
- Both findings documented as defence-in-depth working correctly — positive security indicators

**SIEM Architecture Insight:**
- Centralised log forwarding to Wazuh preserves all events before an attacker can clear local Windows logs
- Demonstrated during T1070.001 simulation — log cleared locally but alert already captured in Elasticsearch index

---

## 🛠️ Technologies Used

| Category | Technology |
|---|---|
| SIEM | Wazuh 4.14.4 (Manager + Indexer + Dashboard) |
| Endpoint Detection | Sysmon v15.15 — Olaf Hartong modular config |
| Linux Auditing | auditd + audispd-plugins |
| Attack Simulation | Atomic Red Team (Red Canary) |
| Virtualisation | VirtualBox 7.x |
| Detection Language | Wazuh XML rules with PCRE2 regex |
| Framework | MITRE ATT&CK v14 |
| OS — SIEM | Ubuntu 24.04 LTS |
| OS — Endpoint | Windows 11 Enterprise Evaluation |
| OS — Linux Agent | Ubuntu 24.04 LTS |
| OS — Attack | Kali Linux 2024 |

---

## 📸 Screenshots

All evidence screenshots organised by phase in the [/screenshots](screenshots/) directory.

**Phase A — Lab Foundation:**
Wazuh Manager deployment, agent enrollment, Sysmon configuration, network setup

**Phase B — Detection Rules:**
Custom rule authoring in nano, XML validation with xmllint, rule loading verification

**Phase C — Attack Simulations:**
Live alerts firing for each detected technique, expanded alert views showing MITRE mapping and forensic field values

**Phase D — Custom Dashboards:**
MITRE ATT&CK heatmap, custom rule overview, endpoint health dashboard, alert severity distribution

---

## 🗺️ Project Phases

- ✅ **Phase A — Lab Foundation**
  4-VM VirtualBox environment, dual-adapter networking, Wazuh all-in-one deployment, multi-platform agent enrollment

- ✅ **Phase B — Detection Engineering**
  10 custom MITRE ATT&CK-mapped rules written in Wazuh XML, PCRE2 regex pattern development, rule validation workflow

- ✅ **Phase C — Attack Simulation**
  Atomic Red Team purple team exercise, 8/10 techniques detected, detection gaps documented with root cause analysis

- ✅ **Phase D — Custom Dashboards**
  Threat overview, MITRE ATT&CK heatmap, endpoint health, alert severity distribution views

- ✅ **Phase E — Incident Response**
  3 professional IR documents with exact forensic values from real Wazuh alerts — timestamps, hashes, process GUIDs

---

## 👤 About

**Ahmed Salam** — Aspiring AI-Augmented SOC Analyst

- 🏆 TryHackMe Top 2% Globally (132 rooms, 30 badges)
- 🎓 CompTIA Security+ Certified
- 📜 SOC Level 1 — TryHackMe (April 2026)
- 🌐 Portfolio: [iamahmedsalam.com](https://iamahmedsalam.com)
- 💼 LinkedIn: [Ahmed Salam](https://www.linkedin.com/in/ahmedsalamnyc)
- 🐙 GitHub: [iamahmedsalam](https://github.com/iamahmedsalam)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
