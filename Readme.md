# 🛡️ SSH Brute Force Detection & SOC Triage Dashboard (MITRE ATT&CK T1110.001)

An end-to-end blue-team detection engineering lab simulating an SSH password brute-force attack from **Kali Linux** against a **Windows OpenSSH** endpoint, monitored and investigated in **Splunk Enterprise** using Windows Security Event Logs and Sysmon telemetry.

---

## 📌 Executive Summary & Objective

The objective of this lab was to simulate credential access tradecraft (`T1110.001` - Brute Force: Password Guessing), identify visibility gaps in native Windows OpenSSH authentication logging, and build a functional 4-panel SOC Triage Dashboard in Splunk to detect, correlate, and attribute the attack.

---

## 🏗️ Lab Architecture & Environment

| Component | Role | IP Address / Hostname | Telemetry / Tools |
| :--- | :--- | :--- | :--- |
| **Attacker Machine** | Threat Simulation | `192.168.23.140` (Kali Linux) | THC-Hydra (`ssh` module) |
| **Target Endpoint** | Monitored Host | `192.168.23.138` (`Windows_for_soc`) | Windows OpenSSH Server (`sshd.exe`), Sysmon, Splunk Universal Forwarder |
| **SIEM Platform** | Detection & Triage | `localhost:8000` | Splunk Enterprise |

```text
[ Kali Linux (192.168.23.140) ]
        │
        │  Hydra SSH Brute Force (Port 22)
        ▼
[ Windows Target: Windows_for_soc (192.168.23.138) ]
   ├── Windows Security Log (Event IDs 4625 & 4624)
   └── Sysmon Operational Log (Event ID 3 - Network Connection)
        │
        │  Splunk Universal Forwarder
        ▼
[ Splunk Enterprise SIEM ] ──► 4-Panel SOC Triage Dashboard
```

---

## ⚔️ Attack Simulation

Using THC-Hydra on Kali Linux, a dictionary attack was launched against the target user account (`Abhishek`) over SSH (TCP Port 22):

```bash
hydra -l Abhishek -P wordlist.txt 192.168.23.138 ssh
```

![Kali Linux Hydra Attack](Image/Kail_linux)

---

## 📊 Splunk SOC Triage Dashboard

![Splunk SSH Brute Force Dashboard](Images/Dashboard)

### Dashboard Panels & SPL Queries

#### 1. Total Failed SSH Logins (KPI Counter)
Tracks failed authentication attempts specifically handled by the OpenSSH daemon (`sshd.exe`).

```spl
host=Windows_for_soc EventCode=4625 (Caller_Process_Name="*sshd.exe" OR Process_Name="*sshd.exe")
| stats count
```

#### 2. Successful SSH Compromise Alert (KPI Counter)
Filters out Windows OpenSSH's unauthenticated pre-login sandbox sessions (`sshd` / `ANONYMOUS LOGON`) to isolate actual user logons following brute-force waves.

```spl
host=Windows_for_soc EventCode=4624 Logon_Process="sshd"
| rex field=_raw "New Logon:[\s\S]*?Account Name:\s+(?<Logged_In_User>[^\r\n]+)"
| where Logged_In_User!="sshd" AND Logged_In_User!="ANONYMOUS LOGON" AND Logged_In_User!="SYSTEM" AND Logged_In_User!="-"
| stats count
```

#### 3. Attack Timeline Spike (Timechart)
Visualizes high-frequency authentication bursts in 1-minute buckets to distinguish automated Hydra spikes from normal human typos.

```spl
host=Windows_for_soc (EventCode=4624 OR EventCode=4625) (Logon_Process="sshd" OR Caller_Process_Name="*sshd.exe")
| eval Status=if(EventCode=4625, "Failed Login (4625)", "Successful Login (4624)")
| timechart span=1m count by Status
```

#### 4. Attacker & Target Network Attribution Table (Sysmon Correlation)
Correlates endpoint process activity (`sshd.exe`) with network socket connections on port 22 to identify the external source IP.

```spl
host=Windows_for_soc EventCode=3 Image="*sshd.exe" DestinationPort=22
| stats count as Connection_Count by SourceIp, DestinationIp, Image
| rename SourceIp as "Attacker IP", DestinationIp as "Target Host IP"
```

---

## 🔍 Key SOC Investigation Findings

During log analysis, two critical Windows OpenSSH logging behaviors were uncovered and resolved:

1. **Missing Source IP in Windows Event ID 4624/4625:**
   * Unlike standard RDP or SMB logons, Windows OpenSSH authenticates locally via `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` after accepting the TCP socket, leaving `Source Network Address` blank (`-`) in Security logs.
   * **Resolution:** Correlated `sshd.exe` process activity with **Sysmon Event ID 3** (`DestinationPort=22`) to reliably attribute the attack to `192.168.23.140`.

2. **Pre-Authentication Sandbox Sessions Inflating Event ID 4624:**
   * Upon every incoming TCP connection on port 22, OpenSSH spins up a restricted privilege-separation sandbox process (`sshd.exe` child worker), generating an `EventCode=4624` logon event *before* password verification occurs—even if all password attempts fail.
   * **Resolution:** Extracted the `New Logon -> Account Name` field via SPL `rex` and excluded virtual/sandbox accounts (`sshd`, `ANONYMOUS LOGON`, `SYSTEM`) to eliminate false positives.

---

## 🛡️ Containment & Remediation Recommendations

* **Enforce Key-Based Authentication:** Disable password authentication in `C:\ProgramData\ssh\sshd_config` (`PasswordAuthentication no`) to neutralize brute-force and password-spraying attacks.
* **Implement Network-Level Blocking / Rate Limiting:** Block the malicious source IP (`192.168.23.140`) via Windows Defender Firewall and restrict SSH port 22 access to authorized management subnets/VPNs.
* **Account Hardening & Credential Reset:** Reset credentials for the compromised account (`Abhishek`) and enforce strong account lockout policies.

---

## 👤 Author

**Abhishek Dahikar**  
* [LinkedIn](https://www.linkedin.com/in/abhishek-dahikar-343413384)  
* [GitHub](https://github.com/abhishek1-2)
