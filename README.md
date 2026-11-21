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
