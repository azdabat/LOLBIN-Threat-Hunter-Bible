# wevtutil.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`wevtutil.exe` manages Windows Event Logs (query/clear/export). Attackers abuse it mainly to **erase logs**, reduce visibility, and hide lateral movement. It can appear in ransomware, post-exploitation cleanup, and living-off-the-land anti-forensics.

Common malicious patterns:
- `wevtutil cl <log>` to wipe PowerShell, Security, Sysmon or Operational logs  
- Execution by Office apps, browsers, script hosts, or odd service parents  
- Encoded command wrappers  
- Mid-chain usage right before credential theft, privilege escalation, or staging activity

Detection focuses on context, destructive intent, and unusual parents—not legitimate admin log maintenance.

---

## 2. MITRE ATT&CK
- **T1070 – Indicator Removal on Host**
- **T1565.001 – Stored Data Manipulation**

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: wevtutil.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let lookback = 7d;
let HighRisk = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","services.exe","svchost.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "wevtutil.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         lcmd = tolower(Cmd)
// Suspicious conditions: destructive log ops, script/encoded wrappers, odd parents
| where ParentImage !in (AllowedParents)
   or lcmd has " cl "                              // log clearing
   or lcmd has_any ("cl ","clear-log","epl ")      // clear/export patterns
   or lcmd has_any (".ps1",".js",".vbs",".hta","-enc","frombase64string")
   or lcmd has_any ("http://","https://")          // extremely rare but shouldn't happen
| extend Reason =
    case(
        lcmd has_any ("cl ","clear-log"),          "Log clearing operation",
        lcmd has "epl ",                           "Log export outside normal parents",
        lcmd has_any (".ps1",".js",".vbs",".hta"), "Script-based wevtutil execution",
        lcmd has_any ("-enc","frombase64string"),  "Encoded command wrapper",
        ParentImage !in (AllowedParents),          "Unusual parent process",
        true,                                      "Rare wevtutil usage"
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
`parent` → **`wevtutil.exe`** → (child processes, if any)

**Red flags:**
* **Parent:** Office application, browser, `mshta`/`wscript`, or suspicious services.
* **Timing:** `wevtutil` invoked right after suspicious PowerShell or credential access activity.
* **Frequency:** `wevtutil` used multiple times in a short window (log tampering attempt).

### 4.2. File/Log Activity

Pivot into `DeviceEvents` and `DeviceFileEvents` **±1h**:

**Look for:**
* Prior PowerShell/AMSI bypass attempts.
* Access to Security/Sysmon/PowerShell logs followed by clearing (`cl`).
* Temporary files created during `.evtx` (export) manipulation.

### 4.3. Network Behaviour

Check `DeviceNetworkEvents` around the execution:

* **Staging/Exfil:** Network changes after log clearing can indicate staging or data exfiltration.
* **Infrastructure:** First-seen domains or direct IPs right after cleanup.
* **Anomaly:** It is **rare** for legitimate log maintenance to coincide with outbound network traffic.

### 4.4. Identity & Scope

* **Prioritize:** Escalate immediately if **`Privileged == Yes`**.
* **Review:**
    * Multiple hosts with `wevtutil cl` (clearing) around the same time.
    * Same user clearing logs across different endpoints.
    * M365/Azure sign-in anomalies aligning with the timestamp.

---

## 5. Baselining & Suppression

Record legitimate `wevtutil` usage for 2–4 weeks.

**Common Benign Cases:**
* Backup agents exporting logs (`epl`).
* Monitoring tools performing routine queries.
* Known maintenance scripts.

**Warning:** Never globally allow `wevtutil cl` (clearing) patterns without strong justification.

### Production Guidance:

* **High severity:** Any log clearing (`cl`) from non-backup parents.
* **Medium:** Encoded/scripted wrappers around `wevtutil`.
* **Low:** Basic log queries with valid parents.

## 6. Operational Notes

This rule is fully standalone—no external Threat Intelligence (TI) required.

It focuses on **destructive operations**, **forensic tampering**, and mid-chain abuse consistent with ransomware, stealthy lateral movement, and post-exploitation cleanup.
