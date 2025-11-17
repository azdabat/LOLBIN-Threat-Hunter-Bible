# forfiles.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`forfiles.exe` is a built-in Windows utility for enumerating files and executing a command for each match. Attackers abuse it to:
- Launch payloads via `/c` and `/p` switches
- Proxy execution of PowerShell, cmd, wscript, mshta, rundll32
- Load scripts or binaries from user-writable paths, SMB shares, or temp staging
- Perform mid-chain execution where the goal is to hide behind a signed binary

We’re not flagging forfiles usage itself—only abnormal patterns inconsistent with admin/IT workflows.

---

## 2. MITRE ATT&CK
- **T1005 – Data from Local System**
- (Commonly overlaps with proxy execution / T1218-style behaviour)

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: forfiles.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let Lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "forfiles.exe"
| extend ProcessCommandLineText = tostring(ProcessCommandLine),
         ParentExecutableName = tostring(InitiatingProcessFileName),
         ParentProcessCommandLineText = tostring(InitiatingProcessCommandLine),
         LowercaseProcessCommandLine = tolower(ProcessCommandLineText)
| where ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe")
   or LowercaseProcessCommandLine has_any ("/c","/p","/m","/d")
   or LowercaseProcessCommandLine has_any (".ps1",".js",".vbs",".hta","-enc","frombase64string")
   or LowercaseProcessCommandLine has_any ("powershell","cmd /c","wscript","cscript","mshta","rundll32")
   or LowercaseProcessCommandLine has_any ("http://","https://",":\\users\\","\\appdata\\","\\temp\\",":\\programdata\\")
| extend DetectionReason =
    case(
        LowercaseProcessCommandLine has_any (".ps1",".js",".vbs",".hta"),"Script payload",
        LowercaseProcessCommandLine has_any ("http://","https://"),"URL loader",
        LowercaseProcessCommandLine has_any ("-enc","frombase64string"),"Encoded payload",
        LowercaseProcessCommandLine has_any ("powershell","mshta","wscript","rundll32"),"Proxy chain",
        LowercaseProcessCommandLine has_any (":\\users\\","\\temp\\"),"User-writable payload",
        ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe"),"Unexpected parent",
        true,"Rare forfiles usage"
    )
| extend PrivilegedAccount = iif(AccountName in (HighRiskAccounts),"Yes","No")
| project Timestamp,DeviceId,DeviceName,AccountName,PrivilegedAccount,
          FileName,ProcessCommandLineText,ParentExecutableName,
          ParentProcessCommandLineText,DetectionReason,ReportId
| order by Timestamp desc

```

## 4. Hunter Directives & L3 Pivot Strategy

### 4.1. Process Chain

Rebuild the process tree:
`parent` → **`forfiles.exe`** → `child command`

**Flags to look for:**
* **Parents:** Office applications, browsers, mail clients, script hosts.
* **Children:** `PowerShell`, `cmd`, `rundll32`, `mshta`, `wscript`, `cscript`, `curl`, `certutil` (all are common initial execution targets).
* `/c` invoking scripts or binaries from user directories (e.g., `%TEMP%`, `%APPDATA%`).

### 4.2. File Activity

Pivot to `DeviceFileEvents` **±1h** around the hit:

* **Staging Indicators:** Look for new EXE/DLL/PS1/VBS/JS created or modified **before** the `forfiles` command runs, typically in `%TEMP%`, `%AppData%`, `%ProgramData%`, or `Downloads`.
* **Behavior:** Identify if the EXE/DLL was written → executed → removed shortly after.

### 4.3. Network Behaviour

Check `DeviceNetworkEvents` around the hit:

* **Traffic:** Outbound traffic right after `forfiles` triggers a payload.
* **Infrastructure:** Bare IP connections, newly-observed domains, odd ports.
* **Correlation:** Look for URLs seen directly in `/c` commands (e.g., used by `curl`, PowerShell download cradles, or `mshta`).

### 4.4. Identity & Scope

* **User Role:** Note if `Privileged == Yes` for immediate escalation.
* **Scope Check:**
    * Look for multiple suspicious `forfiles` executions from the same user.
    * Check for recent risky sign-ins or MFA spam associated with the user.
    * See if the `forfiles` pattern is repeating across multiple hosts (campaign-level activity).

---

## 5. Baselining & Suppression

* **Baseline:** Record normal `forfiles` usage over 2–4 weeks.
* **Typical Legitimate Use Cases:**
    * IT/scripts cleaning temp folders.
    * Log rotation jobs.
    * Vendor tools using `forfiles` for maintenance.
* **Tuning:** Allow only **specific known-good command lines**.
* **Maintenance:** Re-baseline after significant software rollouts.

### Severity Guidance:

* **High:** Encoded commands, script proxies, remote URLs.
* **Medium:** `/c` running unsigned EXEs from user paths.
* **Low:** Benign cleanup jobs with expected parents.

## 6. Operational Notes

This is a clean, native rule—no Threat Intelligence (TI) feeds required.

The rule's intent is to cover real-world abuse where `forfiles` is used as a **stealth launcher** or **file-iteration execution proxy**, without flagging standard cleanup or maintenance routines.
