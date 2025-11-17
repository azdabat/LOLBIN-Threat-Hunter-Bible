# regsvr32.exe LOLBIN Detection (L2/L3 – Production)

## 1. Threat Overview

`regsvr32.exe` is a signed Windows binary used to register and unregister COM DLLs. Attackers abuse it as a LOLBIN to:

- Execute **remote scriptlets** (`.sct`) via `scrobj.dll` and the `/i:` argument (classic *Squiblydoo* pattern).
- Proxy execution of **malicious DLLs** from user-writable or network locations.
- Bypass AppLocker / allow-listing by running attacker-controlled content through a trusted binary.
- Hide execution behind **rare or user-facing parent processes** (Office, browsers, RMM/IT tools).
- Run **fileless chains** where the scriptlet or DLL performs in-memory payload loading.

Effective detection focuses on **command-line patterns, DLL/scriptlet paths, parent process context and account type**, not on `regsvr32.exe` alone.

---

## 2. MITRE ATT&CK Techniques

- **T1218.010 – Signed Binary Proxy Execution: regsvr32**  
- **T1059 – Command and Scripting Interpreter** (via scriptlets / scripts invoked through regsvr32)  
- **T1105 – Ingress Tool Transfer** (when used to fetch and execute remote scriptlets/DLLs)  

---

## 3. Advanced Hunting Query (MDE)

The following query is written for **Microsoft Defender for Endpoint – Advanced Hunting**. It focuses on:

- Remote or suspicious `/i:` arguments (`.sct`, URLs, user-writable paths).  
- Known Squiblydoo patterns (e.g. `scrobj.dll`, `/u`, `/n`, `/s`, `/i:`).  
- Rare parents and privileged accounts.

```kql
let lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe","winlogon.exe"]);
let RemoteTokens = dynamic(["http://","https://","\\\\"]);
let ScriptletTokens = dynamic([".sct","scrobj.dll"]);
let UserWriteTokens = dynamic(["\\Users\\","\\AppData\\","\\Temp\\","\\ProgramData\\"]);
let QuietFlags = dynamic([" /s"," /u"," /n"," /i:","/s ","/u ","/n ","/i:"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "regsvr32.exe"
| extend ParentImage = tostring(InitiatingProcessFileName), ParentCmd = tostring(InitiatingProcessCommandLine), Cmd = tostring(ProcessCommandLine)
| extend HasRemote = Cmd has_any(RemoteTokens),
         HasScriptlet = Cmd has_any(ScriptletTokens),
         HasUserWritePath = Cmd has_any(UserWriteTokens),
         HasQuietFlags = Cmd has_any(QuietFlags),
         RareParent = iif(ParentImage !in (AllowedParents), 1, 0),
         PrivilegedAccount = iif(AccountName in (HighRiskAccounts), "Yes", "No")
| where RareParent == 1
    or HasRemote
    or HasScriptlet
    or HasUserWritePath
    or HasQuietFlags
| extend SuspiciousReason = case(
    HasRemote and HasScriptlet, "regsvr32 using remote scriptlet (Squiblydoo-style).",
    HasScriptlet, "regsvr32 loading scriptlet or scrobj.dll.",
    HasRemote, "regsvr32 using remote path/URL.",
    HasUserWritePath, "regsvr32 pointing at DLL/scriptlet in user-writable path.",
    HasQuietFlags, "regsvr32 running with quiet / non-interactive flags.",
    RareParent == 1, "regsvr32 spawned from rare parent process.",
    PrivilegedAccount == "Yes", "regsvr32 executed under a privileged account.",
    "Unusual regsvr32 usage."
)
| project Timestamp, DeviceId, DeviceName, AccountName, PrivilegedAccount, FileName, Cmd, ParentImage, ParentCmd, InitiatingProcessAccountName, ReportId, SuspiciousReason
| order by Timestamp desc

```

# Regsvr32.exe Hunting Rule & L3 Pivot Strategy

This document outlines a high-fidelity hunting rule targeting malicious `regsvr32.exe` execution (e.g., Squiblydoo-style abuse) and provides a structured Level 3 (L3) pivot strategy for validation.

## 3. High-Fidelity Detection Properties

This hunting rule is focused on identifying `regsvr32.exe` abuse related to proxy execution of scripts and DLLs.

### Key Properties

* **Abuse Analysis:** Uses command-line analysis to catch Squiblydoo-style abuse and DLL/scriptlet proxy execution.
* **Contextual Filtering:** Flags rare parent processes (Office, browsers, RMM, scheduled tasks) without hard-coding specific application names.
* **Triage Aid:** Provides a clear `SuspiciousReason` for quick triage by the security operations center (SOC) team.
* **Impact Prioritization:** Surfaces `PrivilegedAccount` status to highlight higher-impact events immediately.

## 4. L3 Pivot Strategy

Once a hit is generated, treat `regsvr32.exe` as part of a larger execution chain, not the root cause or end of the story.

### 4.1. Expand Process Context

Query `DeviceProcessEvents` for the same `DeviceId` and `ReportId` (or a **±2 hour** window).
Build the execution chain: `parent` → **`regsvr32.exe`** → `children`

Specifically look for:

* **Child processes that should not normally follow `regsvr32.exe`:**
    * `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`
    * `cmd.exe`, custom loaders, or other Living Off the Land Binaries (LOLBINs).
* Evidence that the loaded DLL/scriptlet is spawning additional payloads.

### 4.2. File System Activity

Pivot into `DeviceFileEvents` for the same host **±1 hour**.

**Look for:**

* DLLs or scriptlets (`.sct`) located in high-risk, user-writable directories:
    * `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `ProgramData`, user profile paths.
* Files created or modified shortly before the `regsvr32` event.

**Check whether:**

* The DLL/scriptlet path in the Command Line (`Cmd`) matches newly created files.
* Those files were executed again after registration.

### 4.3. Network Behaviour

If the detection indicates remote activity (`HasRemote` is true) or the `Cmd` contains URLs/UNC paths:

Pivot to `DeviceNetworkEvents`:

* Identify remote hosts, ports, and protocols used around the time of execution.
* Check if other hosts in the environment are contacting the same host/path.
* Determine if `regsvr32` is:
    * Pulling a remote scriptlet (download-and-execute).
    * Acting as a loader for content hosted externally or on a file share.

### 4.4. Identity & Scope

Identify:

* The user or service account running `regsvr32`.
* Whether it is an admin, service, or high-value account (e.g., DBA, domain admin).

Check for:

* Other suspicious activity from the same account (unusual logons, MFA prompts, lateral movement).
* Similar `regsvr32` usage across multiple endpoints.

## 5. Baselining and Suppression

`Regsvr32` can be used legitimately by installers and some legacy applications. Baselining is essential for a production-safe rule.

### Baseline Legitimate `regsvr32` Usage (14–30 days)

Capture all `regsvr32` activity for context:

* Common parent processes (e.g., trusted installers, configuration tools).
* Typical DLL paths (e.g., vendor or OS DLLs under `System32`, `Program Files`).
* Timing patterns (install windows, maintenance periods).

### Document Known Good Patterns

Examples:

* Software installation routines referencing vendor DLLs under `C:\Program Files\Vendor\App\`.
* Internal maintenance tools that register DLLs during upgrades.
* OS components registering DLLs from `C:\Windows\System32\`.

### Create Tight Allow-Patterns

Avoid broad exclusions like “ignore all `regsvr32.exe`.” Instead, define precise exceptions, e.g.:

* `ParentImage == "msiexec.exe" AND Cmd has "C:\\Program Files\\Vendor\\App\\"`
* `Cmd has "C:\\Windows\\System32\\" AND AccountName == "SYSTEM"`

Implement these as:

* Additional `where not(...)` clauses in the query when promoting to a scheduled rule, or
* Suppression conditions in the analytics rule platform.

### Re-Validate After Change

Re-baseline and re-tune after:

* Large application deployments or upgrades.
* OS migrations.
* Changes in deployment tooling (e.g., new RMM, new installer frameworks).

## 6. Turning This Detection Into Reusable Intel (Optional)

For confirmed malicious `regsvr32` activity, convert the detection into durable intelligence.

**Record:**

* The full command line (including `/i:` argument, scriptlet/DLL location).
* Any remote hosts or paths used (HTTP URLs, UNC shares).
* Hashes and locations of DLLs/scriptlets involved.

**Feed back into:**

* Future hunts (search for the same DLL/scriptlet names or URL patterns).
* Detection tuning (add explicit indicators to lower analyst effort next time).

**Track:**

* Whether attackers reuse the same scriptlet or hosting infrastructure.
* Whether `regsvr32` is part of a broader pattern (e.g., alongside `mshta.exe`, `rundll32.exe`, `powershell.exe`).
