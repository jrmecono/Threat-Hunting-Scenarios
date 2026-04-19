
# 🔍 Threat Hunting Scenarios

> A collection of hands-on SOC analyst labs simulating real-world attack detection, threat hunting, and incident response — built on Microsoft Sentinel, Defender for Endpoint, and KQL.

---

## 🧰 Tools & Technologies

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-00A4EF?style=for-the-badge&logo=microsoft&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-FFB900?style=for-the-badge&logo=azuredataexplorer&logoColor=black)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-E22C29?style=for-the-badge&logo=target&logoColor=white)

---

## 📂 Scenarios

| # | Scenario | Threat Type | Key Skills | Framework |
|---|----------|-------------|------------|-----------|
| 01 | [Brute Force Detection](./01-Brute-Force-Detection/README.md) | External RDP Brute Force | Alert Rule Design · Entity Mapping · Incident Response | NIST 800-61 |
| 02 | [Internal Port Scan Detection](./02-Internal-Port-Scan-Detection/README.md) | Internal Reconnaissance | Network Anomaly Hunting · Process Correlation · KQL Pivoting | MITRE ATT&CK |
| 03 | [Data Exfiltration Detection](./03-Data-Exfiltration-Detection/README.md) | Insider Threat / Data Theft | File & Process Analysis · Kill Chain Mapping · DLP Gap Analysis | MITRE ATT&CK |

---

## 🗂️ Repository Structure

```
Threat-Hunting-Scenarios/
│
├── README.md                              ← You are here
│
├── 01-Brute-Force-Detection/
│   ├── README.md
│   ├── screenshots/
│   └── queries/
│
├── 02-Internal-Port-Scan-Detection/
│   ├── README.md
│   ├── screenshots/
│   └── queries/
│
└── 03-Data-Exfiltration-Detection/
    ├── README.md
    ├── screenshots/
    └── queries/
```

---

## 🧠 What These Labs Demonstrate

**Detection Engineering**
Designed and deployed custom Sentinel analytics rules using KQL — including entity mapping, alert grouping, MITRE ATT&CK categorization, and automated incident creation.

**Threat Hunting**
Conducted proactive hunts across `DeviceNetworkEvents`, `DeviceProcessEvents`, and `DeviceFileEvents` — pivoting between tables using timestamps to reconstruct attacker behavior from hypothesis to confirmed IOC.

**Incident Response**
Worked incidents end-to-end following the **NIST 800-61 Incident Response Lifecycle** — from detection and triage through containment, eradication, documentation, and formal closure.

**MITRE ATT&CK Mapping**
Identified and documented TTPs across all three scenarios including T1110 (Brute Force), T1046 (Network Service Discovery), T1560.001 (Archive Collected Data), T1048 (Exfiltration), and T1059.001 (PowerShell).

---

## 📊 MITRE ATT&CK Coverage

| Technique ID | Technique Name | Scenario |
|---|---|---|
| T1110 | Brute Force | 01 — Brute Force Detection |
| T1046 | Network Service Discovery | 02 — Internal Port Scan |
| T1059.001 | PowerShell Execution | 02 & 03 |
| T1105 | Ingress Tool Transfer | 02 & 03 |
| T1560.001 | Archive Collected Data via Utility | 03 — Data Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | 03 — Data Exfiltration |

---

## 💡 Key Takeaways

- Real-world SOC workflows require correlating data across **multiple log sources simultaneously** — no single table tells the full story
- Proactive **threat hunting** catches what reactive alerting misses — especially insider threats with no external indicators
- Every finding should map back to a **framework** (MITRE ATT&CK, NIST) to contextualize risk and drive meaningful remediation
- Hardening recommendations matter as much as detection — identifying **security gaps** and proposing controls is part of the analyst role

---

*Built as part of a hands-on SOC analyst training series focused on real-world detection engineering, threat hunting, and incident response workflows.*
