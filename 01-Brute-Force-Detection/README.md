# 🛡️ Brute Force Detection & Incident Response — Microsoft Sentinel + Defender for Endpoint

**Tools Used:** Microsoft Sentinel · Microsoft Defender for Endpoint · Azure Virtual Machines · KQL · Log Analytics Workspace · MITRE ATT&CK Framework  
**Frameworks:** NIST 800-61 Incident Response Lifecycle  
**Skills Demonstrated:** Threat Detection · SIEM Configuration · Incident Triage · KQL Query Writing · Network Hardening

---

## 📋 Overview

This lab simulates a real-world SOC workflow: designing a custom detection rule in Microsoft Sentinel, triggering a brute force incident, and working it to closure following the **NIST 800-61 Incident Response Lifecycle**. Every step mirrors what an analyst would do in a live environment.

---

## 🔧 Pre-Lab Setup

Before beginning, the following were provisioned and confirmed operational:

- ✅ Azure Virtual Machine created and running
- ✅ VM onboarded to **Microsoft Defender for Endpoint (MDE)**
- ✅ Logs flowing into the **Log Analytics Workspace** connected to Microsoft Sentinel

> 📸 **Screenshot:** *Azure portal showing VM running + MDE onboarding status (Device inventory)*

---

## Part 1 — Creating the Detection Rule (Brute Force Alert)

### Objective
Build a **Scheduled Analytics Rule** in Microsoft Sentinel that fires when the same remote IP fails to log into the same host **10 or more times within 5 hours** — a classic brute force pattern.

### KQL Detection Query

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

This query is run against the `DeviceLogonEvents` table, which receives forwarded authentication logs from Defender for Endpoint.

> 📸 **Screenshot:** *KQL query results in Log Analytics showing RemoteIP, DeviceName, and EventCount columns*

---

### Analytics Rule Configuration

Navigated to **Sentinel → Analytics → + Create → Scheduled Query Rule** and configured:

| Setting | Value |
|---|---|
| Rule Status | Enabled |
| MITRE ATT&CK Tactics | Credential Access — T1110 (Brute Force) |
| Run Query Every | 4 hours |
| Lookup Data For Last | 5 hours |
| Entity Mappings | `RemoteIP` → IP entity · `DeviceName` → Host entity |
| Alert Grouping | All alerts grouped into 1 incident per 24 hours |
| Incident Creation | Automatic |
| Stop Rule After Alert | Yes (24 hours) |

> 📸 **Screenshot:** *Sentinel Analytics rule configuration page — General tab*

> 📸 **Screenshot:** *Entity mapping configuration (RemoteIP + DeviceName)*

> 📸 **Screenshot:** *Completed rule visible in the Analytics rules list*

---

## Part 2 — Triggering the Alert

To generate the incident, the detection rule was triggered by ensuring sufficient `LogonFailed` events existed in the logs. If logs were insufficient, additional failed RDP login attempts were made against the VM to meet the 10-attempt threshold.

> 📸 **Screenshot:** *Sentinel Incidents panel showing the newly created brute force incident*

---

## Part 3 — Working the Incident (NIST 800-61 Lifecycle)

---

### 🔵 Phase 1: Preparation

- Roles, responsibilities, and runbooks were documented prior to the exercise
- Sentinel, MDE, and Log Analytics were confirmed operational
- Detection rules, entity mappings, and incident automation were validated

---

### 🟡 Phase 2: Detection & Analysis

**Step 1 — Validate and Assign**

- Incident confirmed as **active** in Sentinel → Threat Management → Incidents
- Incident assigned to self; status set to **Active**

> 📸 **Screenshot:** *Incident detail page showing status = Active, assigned owner*

**Step 2 — Investigate**

Launched the investigation graph via **Actions → Investigate** to visualize entity relationships.

**Findings from investigation:**
- The alert was triggered by **6 different remote IP addresses** targeting **2 different hosts**
- All suspicious IPs and affected hostnames were documented in the incident notes

> 📸 **Screenshot:** *Sentinel Investigation graph showing IP entities connected to host entities*

**Step 3 — Verify No Successful Logons**

Cross-referenced suspicious IPs against successful logon events using the following query:

```kql
let TargetDevice = "windows-target-1"; // Replace with your VM name
let SuspectIP = "89.116.158.44";       // Replace with suspicious IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

**Result:** No successful logons were found from any of the flagged IPs. The brute force was unsuccessful.

> 📸 **Screenshot:** *KQL query returning 0 results for LogonSuccess from suspect IPs*

---

### 🔴 Phase 3: Containment, Eradication & Recovery

**Containment**

Updated the **Network Security Group (NSG)** attached to the VM to block all inbound RDP traffic except from my local machine's IP address, eliminating public internet exposure.

Documented in incident notes:
> *"NSG was locked down to block all public RDP access. Only the administrator's IP is permitted. Corporate policy was proposed to enforce this posture across all VMs via Azure Policy."*

> 📸 **Screenshot:** *Azure NSG inbound rules — showing RDP restricted to personal IP only*

**Eradication**

- Brute force was not successful; no unauthorized access occurred
- No malware or persistence mechanisms were found
- No further eradication steps required

**Recovery**

- VM confirmed operational with no disruption to availability
- Systems restored to normal operational status without additional intervention

---

### 🟢 Phase 4: Post-Incident Activities

**Lessons Learned**

- VMs should never have NSGs left open to the public internet by default
- Azure Policy can enforce NSG hardening organization-wide as a preventive control
- Alert rule logic could be enhanced to only fire on brute force attempts that include at least one successful logon, reducing false positive noise

All findings, evidence, and recommendations were recorded directly in the Sentinel incident notes.

> 📸 **Screenshot:** *Sentinel incident notes/comments panel showing documented findings*

---

### ⚫ Phase 5: Closure

- Reviewed all documented notes and evidence within the incident
- Confirmed the incident was fully investigated and no active threat remained
- Incident closed in Sentinel as: **True Positive — Resolved**

> 📸 **Screenshot:** *Incident closed as True Positive in Sentinel*

---

## 🗂️ Summary

| Phase | Action Taken |
|---|---|
| Preparation | Sentinel + MDE environment validated; runbook reviewed |
| Detection | Custom KQL rule created; alert fired on 10+ failed logons in 5h |
| Analysis | 6 IPs, 2 hosts identified; no successful logons confirmed |
| Containment | NSG locked down to allow only trusted IP |
| Eradication | No active threat; brute force was unsuccessful |
| Recovery | VM operational; no data loss or compromise |
| Post-Incident | Findings documented; Azure Policy hardening proposed |
| Closure | Incident closed as True Positive in Microsoft Sentinel |

---

## 📁 Repository Structure

```
brute-force-detection-lab/
│
├── README.md                  ← This file
├── screenshots/
│   ├── 01-vm-mde-onboarding.png
│   ├── 02-kql-query-results.png
│   ├── 03-analytics-rule-general.png
│   ├── 04-entity-mapping.png
│   ├── 05-rule-in-analytics-list.png
│   ├── 06-incident-created.png
│   ├── 07-incident-active-assigned.png
│   ├── 08-investigation-graph.png
│   ├── 09-logonsuccess-query-empty.png
│   ├── 10-nsg-lockdown.png
│   ├── 11-incident-notes.png
│   └── 12-incident-closed.png
└── queries/
    ├── brute_force_detection.kql
    └── verify_successful_logon.kql
```

---

*Built as part of a hands-on SOC analyst training series focused on real-world detection engineering and incident response workflows.*
