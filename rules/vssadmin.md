# vssadmin.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`vssadmin.exe` manages Windows Volume Shadow Copies. Attackers use it primarily for **anti-forensic cleanup** and **ransomware preparation**, deleting backups and shadow copies so recovery is impossible.

Real abuse patterns:
- `vssadmin delete shadows /all /quiet` used early in ransomware chains
- vssadmin invoked by Office apps, browsers, script hosts, or odd service parents
- Encoded loader sequences wrapping vssadmin calls
- Mid-chain execution after initial access but before impact

The goal is to detect destructive or abnormal context—not legitimate backup maintenance.

---

## 2. MITRE ATT&CK
- **T1070 – Indicator Removal on Host**
- **T1565.001 – Stored Data Manipulation**

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: vssadmin.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let lookback = 7d;
let HighRisk = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","services.exe","svchost.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "vssadmin.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         lcmd = tolower(Cmd)
// Suspicious patterns: destructive shadow copy ops, scripts, encoded payloads, unusual parents
| where ParentImage !in (AllowedParents)
   or lcmd has "delete shadows"
   or lcmd has_any ("/all","/quiet","/for=")
   or lcmd has_any (".ps1",".js",".vbs",".hta","-enc","frombase64string")
   or lcmd has_any ("http://","https://")
| extend Reason =
    case(
        lcmd has "delete shadows", "Shadow copy deletion",
        lcmd has_any ("/all","/quiet","/for="), "Destructive VSS operation",
        lcmd has_any ("-enc","frombase64string"), "Encoded command wrapper",
        lcmd has_any (".ps1",".js",".vbs",".hta"), "Script-based vssadmin execution",
        ParentImage !in (AllowedParents), "Anomalous parent process",
        true, "Rare vssadmin usage"
    )
| extend Privileged = iif(AccountName in (HighRisk),"Yes","No")
| project Timestamp, DeviceId, DeviceName, AccountName, Privileged,
          FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, Reason, ReportId
| order by Timestamp desc

```

## 4. Hunter Directives & L3 Pivot Strategy

### 4.1. Process Chain

Rebuild context around the hit:
`parent` → **`vssadmin.exe`** → `child`

**Red flags:**
* **Parent:** Office applications, web browsers, `wscript.exe`, `mshta.exe`, or suspicious services.
* **Child Processes:** Look for follow-on child processes (rare but relevant in staged loaders).
* **Timing:** Shadow deletion shortly after suspicious file drops or mass file activity.

### 4.2. File Activity

Pivot to `DeviceFileEvents` **±1h**:

**Look for ransomware precursors:**
* File encryption patterns.
* Mass file renames or write bursts.
* Dropped EXEs/PS1/JS/VBS in `TEMP`/`AppData` **before** `vssadmin` runs.
* **Confirm signing:** Installer/updater behaviour normally has predictable parents—confirm the signer and known path of any preceding files.

### 4.3. Network Indicators

Check `DeviceNetworkEvents` around the execution:

* **Traffic:** C2 callbacks before or after shadow deletion.
* **Infrastructure:** Bare IPs, TOR exit nodes, previously unseen domains.
* **Context:** Activity from a user workstation or jump host is generally **more suspicious** than benign server-side operations.

### 4.4. Identity & Scope

* **Escalation:** If `Privileged == Yes`, escalate immediately.
* **Scope Check:**
    * Check if the same account invoked `vssadmin` across multiple hosts.
    * See if the user has compromised credentials (risky sign-ins, token anomalies).
    * Look for other LOLBINs fired before/after (e.g., `wmic`, `wbadmin`, `bcdedit`).

---

## 5. Baselining & Suppression

* **Observe:** Record normal `vssadmin` usage for 2–4 weeks.
* **Allow:**
    * Backup agent parents.
    * Vendor-signed maintenance utilities.
    * Known-good `/list shadows` operations.
* **Warning:** Never allow `/all /quiet` patterns without explicit justification.

### Production Guidance:

* **High severity:** Any shadow deletion from a non-backup parent.
* **Medium:** Encoded/scripted `vssadmin` calls.
* **Low:** Benign listing operations.

## 6. Operational Notes

This is a standalone MDE/Sentinel rule—no threat intel dependencies required.

It focuses on **destructive operations**, odd parent chains, and real-world ransomware behaviors while keeping noise extremely low once baselined.
