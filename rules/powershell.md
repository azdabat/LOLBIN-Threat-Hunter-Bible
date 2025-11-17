# powershell.exe LOLBIN Detection (L2/L3 – Production)

## 1. Threat Overview

`powershell.exe` is a legitimate Windows binary and one of the most abused LOLBINs on modern Windows systems. Adversaries use it for:

- **Download & execute**: pulling payloads from HTTP/HTTPS and executing directly in memory.
- **Living-off-the-land**: interacting with the registry, WMI, services, scheduled tasks, and the file system using native cmdlets.
- **Fileless malware**: heavy use of `-EncodedCommand`, `Invoke-Expression`, and in-memory loaders to avoid dropping binaries.
- **Payload staging & lateral movement**: running offensive frameworks (PowerView, PowerSploit, Empire, Covenant, Cobalt Strike loaders).
- **Defense evasion**: disabling logging, tampering with AMSI, or using reflection and obfuscation frameworks.

Effective detection focuses on **command-line behaviour + parent process + account context**, not on treating `powershell.exe` as inherently malicious.

---

## 2. MITRE ATT&CK Techniques

- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
- **T1204 – User Execution** (macros / lures spawning PowerShell)  
- **T1105 – Ingress Tool Transfer** (download of payloads/scripts)  
- **T1562 – Impair Defenses** (disabling logging / AMSI)  

---

## 3. Advanced Hunting Query (MDE)

The following query is written for Microsoft Defender for Endpoint Advanced Hunting and is designed for interactive hunts or as the basis for a scheduled detection. It focuses on **rare parents, network usage, encoded commands, and script-loader behaviour** while still being production-safe.

```kql
let lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe","winlogon.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         ParentCmd   = tostring(InitiatingProcessCommandLine),
         Cmd         = tostring(ProcessCommandLine)
| extend HasRemote = Cmd has_any ("http:","https:"),
         HasScriptLoader = Cmd has_any (".ps1",".psm1",".js",".vbs",".hta","Invoke-Expression","IEX","DownloadString"),
         HasEncoded = Cmd has_any ("-enc","-encodedcommand","FromBase64String"),
         HasAmsiOrLogTamper = Cmd has_any ("amsiUtils","AmsiScanBuffer","Bypass","Set-StrictMode","LogName \"Microsoft-Windows-PowerShell\"","Disable-ModuleLogging"),
         RareParent = iif(ParentImage !in (AllowedParents), 1, 0),
         PrivilegedAccount = iif(AccountName in (HighRiskAccounts), "Yes", "No")
| where RareParent == 1
    or HasRemote
    or HasEncoded
    or HasScriptLoader
    or HasAmsiOrLogTamper
| extend SuspiciousReason = case(
    HasRemote and HasScriptLoader, "Remote script download and execution behaviour",
    HasRemote, "PowerShell making HTTP/S calls (possible C2/download)",
    HasEncoded, "Encoded or heavily obfuscated PowerShell command line",
    HasAmsiOrLogTamper, "Possible AMSI/logging tampering or defense evasion",
    HasScriptLoader, "Script-loader behaviour (IEX/DownloadString/.ps1/.js/.vbs)",
    RareParent == 1, "PowerShell spawned from a rare parent process",
    true, "Unusual PowerShell invocation"
  )
| project Timestamp, DeviceId, DeviceName, AccountName, PrivilegedAccount,
          FileName, Cmd, ParentImage, ParentCmd, InitiatingProcessAccountName,
          ReportId, SuspiciousReason
| order by Timestamp desc

```

Key properties:

- Leverages `InitiatingProcessFileName` and `ProcessCommandLine` for context.
- Treats rare parents and encoded / network‑touching commands as primary signal.
- Provides a `SuspiciousReason` column to explain why the row is interesting.
- Surfaces privileged accounts separately for accelerated triage.

# PowerShell Hunting Rule & L3 Pivot Strategy

This document outlines a high-fidelity hunting rule targeting malicious PowerShell execution and provides a structured Level 3 (L3) pivot strategy for incident validation and scope determination.

## 3. High-Fidelity Detection Properties

This hunting rule is designed to distinguish legitimate automation from suspicious, attacker-controlled command chains.

### Key Properties

* **Contextual Filtering:** Leverages `InitiatingProcessFileName` and `ProcessCommandLine` to separate legitimate automation from suspicious chains.

* **SuspiciousReason Column:** Provides a clear `SuspiciousReason` column explaining the behavioral indicator that flagged each row.

* **Impact Prioritization:** Exposes the `PrivilegedAccount` status so analysts can quickly prioritize impact based on user context.

### Flagged Indicators

The rule flags the presence of several high-risk indicators within the PowerShell command line or execution context:

* **Remote Network Usage:** Indicators such as `Invoke-WebRequest`, `DownloadString`, or external URLs.

* **Obfuscation/Encoding:** Use of `-EncodedCommand`, `FromBase64String`, or other techniques to hide command logic.

* **Script-Loader Patterns:** Execution methods like `IEX`, direct execution of files (`.ps1`, `.js`, `.vbs`, `.hta`).

* **Evasion/Tampering:** Indicators of AMSI or logging tampering.

* **Rare Parent Processes:** PowerShell spawned by unusual parents (e.g., Office applications, web browsers, RMM tools, helpdesk software, or suspicious scheduled tasks).

## 4. L3 Pivot Strategy

Once a hit is generated, the analyst must treat the event as the starting node of a threat graph, not the end of the story.

### 4.1. Expand Process Context

Query `DeviceProcessEvents` for the same `DeviceId` and `ReportId` (or a `±2h` window). Build the process chain: `parent` → `powershell.exe / pwsh.exe` → `children`.

Specifically look for the execution of:

* **Offensive Tools / Reconnaissance:** `whoami.exe`, `net.exe`, `netstat.exe`, `nltest.exe`, `dsquery.exe`, `adfind.exe`, `csvde.exe`, `ntdsutil.exe`.

* **Credential Theft / LSASS Access:** `rundll32.exe` abusing `comsvcs.dll`, suspicious `procdump.exe`, `Taskmgr.exe` abuse, or memory dump tools.

* **Lateral Movement Tools:** `wmic.exe`, `psexec.exe`, `schtasks.exe`, `mstsc.exe`, `wmiprvse.exe`.

* **Archive & Staging:** `7z.exe`, `rar.exe`, `tar.exe`, `makecab.exe`.

* **Ransomware / Encryptors:** Unusual encryption utilities or custom binaries spawned shortly after the PowerShell event.

### 4.2. File System Activity

Pivot into `DeviceFileEvents` for the same device (±1 hour window).

**Look for:**

* Newly-written files (`EXE`, `DLL`, `PS1`, `VBS`, `JS`) in high-risk directories: `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `ProgramData`, and user profile paths.

* Files created immediately before or after the PowerShell event.

* Scripts matching parts of the PowerShell command line (e.g., file names, URLs, function names).

**Confirm whether:**

* PowerShell wrote a script and then executed it.

* PowerShell dropped known offensive tools (e.g., Mimikatz, Cobalt Strike stagers, custom binaries).

### 4.3. Network Behaviour

Use `DeviceNetworkEvents` for the same device/time window.

**Identify:**

* Remote IPs, FQDNs, and ports used for C2 or staging.

* Cleartext HTTP vs. HTTPS connections.

* First-seen infrastructure or rare domains.

**Correlate:**

* Network patterns with command line strings (domains/paths in the command).

* Whether the same destination is used by other hosts.

* Pivot into separate web/socks logs (if available) to confirm data transfer size and direction.

### 4.4. Identity & Scope

Determine the identity and scope of the compromise.

* **Identity:** Was the account a user vs. a service account? Admin vs. normal user? Interactive vs. scheduled execution?

* **Related Anomalies:** Check for related identity anomalies (e.g., unusual sign-ins, impossible travel, risky sign-ins in Azure AD, MFA fatigue) around the same timeframe.

* **Scope:** Is this a single compromised endpoint? Was the same account used on multiple hosts? Are multiple accounts spawning similar PowerShell chains?

## 5. Baselining and Suppression

PowerShell is heavily used in legitimate administration, making baselining essential to avoid drowning analysts in noise.

### Baseline Legitimate Usage (14–30 Days)

Capture all `powershell.exe / pwsh.exe` usage for context:

* Parent images (`ParentImage`).

* Command line patterns (e.g., specific scripts, internal modules).

* Typical times (business hours vs. off-hours).

* System types (servers, workstations, admin jump boxes).

**Summarise by:** ParentImage, command line patterns (normalized), user role/group membership, and device groups.

### Document Known Good Patterns

Typical benign patterns might include:

* Signed internal scripts (`C:\IT\Scripts\Maintenance.ps1`).

* SCCM/Intune/automation tools spawning PowerShell with well-known arguments.

* Monitoring agents using PowerShell for inventory/health checks.

### Create Tight Allow-Patterns

Never wildcard full command lines like `powershell.exe *`. Instead, carve explicit exceptions such as:

* **Specific Parent + Script:** `ParentImage == "ccmexec.exe" AND Cmd has "C:\\Windows\\CCM\\SystemTask.ps1"`

* **Specific Internal Module Path:** `Cmd has "C:\\Company\\Automation\\Run-Backup.ps1"`

Implement suppression either directly in KQL (`where not(...)`) or via detection rule suppression conditions in the security portal.

### Re-Validate Baselines

Always re-validate baselines after any major environmental change (e.g., large software rollouts, migration to new scripting frameworks, modification of admin tooling).

## 6. CTI / MISP / OpenCTI Integration

For confirmed malicious PowerShell activity, the detection must be converted into durable intelligence.

### Extract Technical IOCs

* **Network:** URLs, domains, and IPs referenced in the command line.

* **Files:** Hashes of downloaded scripts, dropped EXEs/DLLs, archives, or tools.

* **Artifacts:** Distinct script artifacts, function names, unique strings, or C2 patterns.

### Model the Event in Your TI Platform

Create or update events in MISP/OpenCTI:

* Link to an Intrusion Set / Actor (if attribution is reasonable).

* Create Campaign or Incident objects.

* Create Observable objects for URLs, hashes, IPs, file names, and registry keys.

**Tag with:**

* Confidence (e.g., `confidence:high`, `medium`).

* Kill chain phase (execution, persistence, C2, exfiltration).

* Detection source (e.g., `LOLBIN-PowerShell-MDE`, `Sentinel analytic name`).

### Feed Back into Detection

Use exported TI (watchlists, indicators) to:

* Flag reuse of the same infrastructure.

* Enrich future PowerShell hits with “known bad” context.

* Track the evolution of the activity (e.g., new URLs/scri
