# schtasks.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`schtasks.exe` is a signed scheduler utility. Adversaries use it to persist payloads, run off SMB shares, launch staged EXEs/PS1/VBS/HTA, or to push mid-chain execution under a trusted binary. Detection hinges on context: who launched it, what it launched, and where the payload lives.

Common abuse patterns:
- Persistence via `schtasks /create` using user-writable paths (AppData, TEMP, ProgramData)
- Remote task creation from Office/mailer/browser parents
- Encoded PowerShell loaders and script proxies
- Mid-chain lateral staging (`schtasks /run /tn <temp task>`)

The goal is not to flag every task operation, only the unusual ones.

---

## 2. MITRE ATT&CK
- **T1053 – Scheduled Task/Job**
- **T1547 – Boot/Logon Autostart**

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: schtasks.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let Lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "schtasks.exe"
| extend ProcessCommandLineText = tostring(ProcessCommandLine),
         ParentExecutableName = tostring(InitiatingProcessFileName),
         ParentProcessCommandLineText = tostring(InitiatingProcessCommandLine),
         LowercaseProcessCommandLine = tolower(ProcessCommandLineText)
| where ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe")
   or LowercaseProcessCommandLine has_any ("/create","/change","/run","/tn","/tr")
   or LowercaseProcessCommandLine has_any (".ps1",".js",".vbs",".hta","-enc","frombase64string")
   or LowercaseProcessCommandLine has_any ("http://","https://",":\\users\\","\\appdata\\","\\temp\\",":\\programdata\\")
| extend DetectionReason =
    case(
        LowercaseProcessCommandLine has_any ("http://","https://"),"URL-based execution",
        LowercaseProcessCommandLine has_any ("-enc","frombase64string"),"Encoded loader",
        LowercaseProcessCommandLine has_any (".ps1",".js",".vbs",".hta"),"Script task execution",
        LowercaseProcessCommandLine has_any ("/create","/change","/run"),"Task modification",
        ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe"),"Unexpected parent",
        true,"Rare schtasks usage"
    )
| extend PrivilegedAccount = iif(AccountName in (HighRiskAccounts),"Yes","No")
| project Timestamp,DeviceId,DeviceName,AccountName,PrivilegedAccount,
          FileName,ProcessCommandLineText,ParentExecutableName,
          ParentProcessCommandLineText,DetectionReason,ReportId
| order by Timestamp desc


```

## 4. Hunter Directives & L3 Pivot Strategy

### 4.1. Process Chain

Rebuild the full process tree around the hit:
`parent` → **`schtasks.exe`** → `child process`

**Red flags:**
* **Parents:** Office applications, web browsers, mail clients, `wscript.exe`, `mshta.exe` (processes that shouldn't be scheduling tasks).
* **Children:** `PowerShell`, `CMD`, `curl`/`wget` clones, `dllhost`, archive tools, RDP tooling.
* **Timing:** Task creation followed by **immediate execution** of an EXE/PS1 from user space (e.g., `%TEMP%` or `%APPDATA%`).

### 4.2. File Activity

Pivot to `DeviceFileEvents` **±1h** around the event timestamp:

**Look for payload writes in:**
* `%AppData%`, `%TEMP%`, `%ProgramData%`.
* **Timing:** EXE/DLL/PS1/VBS/JS created minutes before the scheduled task is set to fire.
* **Signing:** Compare signed vs. unsigned nature of the final payload.

### 4.3. Network Behaviour

Check `DeviceNetworkEvents` **±1h**:

* **Activity:** Outbound network connections following the task execution.
* **Infrastructure:** Bare IPs, odd ports, newly-observed domains.
* **Correlation:** Look for a direct correlation between the `/tr` (task run) payload and the new network traffic.

### 4.4. Identity & Blast Radius

* **User and Role:** Determine the business role of the `AccountName`. If `Privileged == Yes`, escalate immediately.
* **Look for:**
    * Multiple task creations by the same user.
    * Recent risky sign-ins or password resets on that account.
    * The same task name or payload path across multiple endpoints (indicating wider campaign activity).

---

## 5. Baselining & Suppression

* **Baseline first (2–4 weeks):** Record normal `schtasks.exe` behavior across your environment.
    * **Typical Baseline:** Software updaters, agent installers, IT management tools.
* **Tuning:** Allow only **specific known-good command lines** (avoid wildcards).
* **Re-baseline:** Repeat baselining when tooling or patching cycles change.

### For Production Alerting:

* **High severity:** Encoded loaders, remote URLs, or unsigned payloads running from user paths.
* **Medium severity:** `/create` or `/change` executed from untrusted parents.
* **Low severity:** `/run` commands with normal, trusted parents.

## 6. Operational Notes

**Intent:** The primary goal is to catch modern tradecraft where `schtasks` is used as a **persistence launcher**, **mid-chain loader**, or **proxy executor**, while efficiently avoiding noise from routine Windows scheduling. This rule is designed to be standalone, without external CTI or threat-intel dependencies.
