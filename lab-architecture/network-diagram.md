# Lab Architecture — Network Topology & VM Specifications

## Network Design

All four VMs operate on a **VirtualBox Host-Only Adapter** network (`192.168.56.0/24`) for lab communication, with a second **NAT adapter** (gateway `10.0.3.2`) on each VM for internet access. This dual-adapter design was chosen specifically to avoid IP address changes when the host machine connects to different WiFi networks — Host-Only addresses are static regardless of external network conditions.

```
┌─────────────────────────────────────────────────────┐
│              VirtualBox Host-Only Network           │
│                  192.168.56.0/24                    │
│                                                     │
│  ┌─────────────┐    ┌──────────────────────────┐    │
│  │ Kali Linux  │    │     Wazuh Manager        │    │
│  │192.168.56.50│────│     Ubuntu 24.04 LTS     │    │
│  │  Attack VM  │    │     192.168.56.101       │    │
│  └─────────────┘    │     Wazuh 4.14.4         │    │
│                     └──────────┬───────────────┘    │
│                                │                    │
│                 ┌──────────────┴─────────────┐      │
│                 │                            │      │
│  ┌──────────────┴─────────┐  ┌───────────────┴──┐   │
│  │     Windows 11         │  │ Ubuntu 24.04 LTS │   │
│  │     192.168.56.103     │  │ 192.168.56.104   │   │
│  │     Wazuh Agent 001    │  │ Wazuh Agent 002  │   │
│  │     Sysmon v15.15      │  │ auditd           │   │
│  └────────────────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## IP Address Table

| VM | IP Address | Role | OS |
|---|---|---|---|
| VirtualBox Host | 192.168.56.1 | Hypervisor | Windows 10 |
| Wazuh Manager | 192.168.56.101 | SIEM (Manager + Indexer + Dashboard) | Ubuntu 24.04 LTS |
| Windows 11 Endpoint | 192.168.56.103 | Monitored endpoint (Agent 001) | Windows 11 Enterprise Evaluation |
| Ubuntu SOC Agent | 192.168.56.104 | Monitored endpoint (Agent 002) | Ubuntu 24.04 LTS |
| Kali Linux | 192.168.56.50 | Attack machine | Kali Linux 2024 |

## VM Specifications

### Wazuh Manager — 192.168.56.101

| Spec | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Wazuh Version | 4.14.4 (all-in-one: Manager + Indexer + Dashboard) |
| Dashboard Access | `https://192.168.56.101` |
| Agent Listening Port | 1514/TCP |
| Adapter 1 | Host-Only — 192.168.56.101 |
| Adapter 2 | NAT — gateway 10.0.3.2 |
| Custom Rules | `/var/ossec/etc/rules/local_rules.xml` |

### Windows 11 SOC Endpoint — 192.168.56.103

| Spec | Value |
|---|---|
| OS | Windows 11 Enterprise Evaluation |
| Wazuh Agent ID | 001 |
| Sysmon | v15.15 — Olaf Hartong sysmon-modular config |
| Sysmon Channel | `Microsoft-Windows-Sysmon/Operational` |
| Agent Config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Adapter 1 | Host-Only — 192.168.56.103 |
| Adapter 2 | NAT — gateway 10.0.3.2 |
| Atomic Red Team | Installed at `C:\AtomicRedTeam\atomics` |

### Ubuntu SOC Agent — 192.168.56.104

| Spec | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Wazuh Agent ID | 002 |
| Logging | auditd + audispd-plugins |
| Adapter 1 | Host-Only — 192.168.56.104 |
| Adapter 2 | NAT — gateway 10.0.3.2 |

### Kali Linux — 192.168.56.50

| Spec | Value |
|---|---|
| OS | Kali Linux 2024 |
| Role | Adversary simulation / attack machine |
| Tools Used | Atomic Red Team (via Windows), Nmap, xfreerdp |
| Adapter 1 | Host-Only — 192.168.56.50 |
| Adapter 2 | NAT — gateway 10.0.3.2 |

## Network Adapter Configuration

Each VM has two adapters configured in VirtualBox:

**Adapter 1 — Host-Only (`vboxnet0`)**
- Purpose: All lab traffic between VMs
- Subnet: 192.168.56.0/24
- Static IPs assigned per VM
- No dependency on external network — IPs remain stable regardless of host WiFi

**Adapter 2 — NAT**
- Purpose: Internet access for package updates, tool downloads, Atomic Red Team installation
- Gateway: 10.0.3.2
- Each VM gets independent internet access without exposing lab traffic externally

## Design Decisions

**Why Host-Only instead of Bridged?**
Bridged networking assigns IPs from the router's DHCP pool — these change when the host moves between networks (home, office, mobile hotspot). Host-Only addresses are managed entirely by VirtualBox and remain constant. This eliminates a common home lab frustration where agents lose connectivity after a location change.

**Why dual adapters instead of Host-Only only?**
Atomic Red Team installation requires downloading ~200MB of attack definitions from GitHub. Wazuh and OS updates require internet access. The NAT adapter provides this without routing lab attack traffic through the external network.

**Why all-in-one Wazuh instead of distributed?**
For a 2-agent home lab, the all-in-one deployment (Manager + Indexer + Dashboard on a single VM) is the practical choice. Distributed deployment adds complexity without meaningful benefit at this scale. The skills demonstrated — agent enrollment, rule writing, alert analysis — are identical regardless of deployment topology.
