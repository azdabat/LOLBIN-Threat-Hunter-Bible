# rundll32.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview

`rundll32.exe` is a signed Windows utility used to execute DLL exports. Adversaries abuse it as a proxy to:
- Run payload DLLs from user-writable paths, SMB shares or ADS streams.
- Launch EXE/HTA/JS/VBS/SCT via LOLBAS helper DLLs (url.dll, shell32.dll, zipfldr.dll, setupapi.dll, PhotoViewer, shimgvw, desk.cpl).
- Download payloads from remote URLs into INetCache or temp folders.
- Execute stealth mid-chain stages, LSASS dump helpers, and C2 loaders under a trusted process.

Effective detection focuses on **where the DLL/EXE is loaded from** and **which helper DLL/export pair is used**, combined with **parent process context** and **account sensitivity**. We are not treating all `rundll32.exe` as malicious; we zero in on suspicious patterns that match real LOLBAS tradecraft.

---

## 2. MITRE ATT&CK Mapping

- **T1218.011 – System Binary Proxy Execution: rundll32** (DLL/exe proxy, hijacked COM components, LOLBAS helper DLLs).
- **T1105 – Ingress Tool Transfer** (PhotoViewer / shimgvw download helpers into cache).
- **T1564.004 – Hide Artifacts: NTFS Alternate Data Streams** (DLLs/code in ADS).
- **T1059.\*** – Command and Scripting Interpreter (JS/VBS/SCT/HTA via mshtml, setupapi, url.dll).
- **T1574.002 – DLL Side-Loading** (hijacked DLLs/COM servers invoked via rundll32).

---

## 3. Advanced Hunting Query (MDE – Native, Low Noise)

> Usage: run in **Advanced Hunting** (DeviceProcessEvents). Safe as the base for a scheduled rule once baselined. Tune `AllowedParents` and `HighRiskAccounts` to your environment.

```kql
// ======================================================================
// LOLBIN: rundll32.exe Suspicious Usage (LOLbas-Aware)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// Purpose: Catch high-signal rundll32 LOLBAS tradecraft with low noise
// MITRE: T1218.011, T1105, T1564.004, T1059.*, T1574.002
// ======================================================================
let Lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rundll32.exe"
| extend ProcessCommandLineText = tostring(ProcessCommandLine),
         ParentExecutableName = tostring(InitiatingProcessFileName),
         ParentProcessCommandLineText = tostring(InitiatingProcessCommandLine),
         LowercaseProcessCommandLine = tolower(ProcessCommandLineText)
| where ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe","dllhost.exe")
   or LowercaseProcessCommandLine has_any (
        "mshtml,runhtmlapplication"," url.dll,openurl"," url.dll,fileprotocolhandler",
        "photoviewer.dll","shimgvw.dll","shell32.dll,control_rundll",
        "shell32.dll,shellexec_rundll","setupapi.dll,installhinfsection",
        "zipfldr.dll,routethecall","desk.cpl,installscreensaver"
     )
   or LowercaseProcessCommandLine has_any (".js",".vbs",".sct",".ps1",".hta",".inf",".scr")
   or LowercaseProcessCommandLine matches regex @"[:][^\\s]+\.dll(\W|$)"
   or LowercaseProcessCommandLine has_any ("\\\\","http://","https://",":\\users\\","\\temp\\","\\appdata\\",":\\programdata\\")
| extend DetectionReason =
    case(
        LowercaseProcessCommandLine has "mshtml,runhtmlapplication","Scriptlet execution",
        LowercaseProcessCommandLine has_any (" url.dll,openurl"," url.dll,fileprotocolhandler"),"url.dll execution",
        LowercaseProcessCommandLine has_any ("photoviewer.dll","shimgvw.dll"),"Photo viewer proxy",
        LowercaseProcessCommandLine matches regex @"[:][^\\s]+\.dll(\W|$)","ADS DLL execution",
        LowercaseProcessCommandLine has "setupapi.dll,installhinfsection","INF execution",
        LowercaseProcessCommandLine has "zipfldr.dll,routethecall","Zipfldr proxy",
        LowercaseProcessCommandLine has_any ("shell32.dll,control_rundll","shell32.dll,shellexec_rundll"),"Shell32 proxy",
        LowercaseProcessCommandLine has_any ("http://","https://"),"Remote URL execution",
        ParentExecutableName !in ("explorer.exe","svchost.exe","services.exe","dllhost.exe"),"Unexpected parent",
        true,"Rare rundll32 invocation"
    )
| extend PrivilegedAccount = iif(AccountName in (HighRiskAccounts),"Yes","No")
| project Timestamp,DeviceId,DeviceName,AccountName,PrivilegedAccount,
          FileName,ProcessCommandLineText,ParentExecutableName,
          ParentProcessCommandLineText,DetectionReason,ReportId
| order by Timestamp desc

```

## 4. Hunter Directives & L3 Pivot Strategy

Treat each hit as **“mid-chain execution under a trusted binary,”** not as a standalone IOC. Use these pivots to decide if this is a real intrusion, tooling, or noise.

### 4.1. Process Tree & Context

**Rebuild the chain**
Re-query `DeviceProcessEvents` on the same `DeviceId` and `ReportId`.
Draw the process chain: `grandparent` → `parent` → **`rundll32.exe`** → `children`.

**Red flags:**
* **Unusual parents:** `winword.exe`, `excel.exe`, browsers, mail clients, `wscript.exe`, `mshta.exe`.
* **Children:** `powershell.exe`, `cmd.exe`, `reg.exe`, `procdump.exe`, `rundll32.exe` spawning another `rundll32.exe`, LSASS dump helpers (`comsvcs.dll` pattern), archivers, remote admin tools.

**Check command line intent**
Confirm which LOLBAS pattern you hit:
* `url.dll` → payload via `.url`, `.hta` or EXE.
* `setupapi.dll,InstallHinfSection` → INF AWL bypass/scriptlet.
* `zipfldr.dll,RouteTheCall` → EXE via compressed folder library.
* `desk.cpl,InstallScreenSaver` → `.scr` execution.
* `PhotoViewer.dll / shimgvw.dll` → download to cache and follow-on execution.

**Ask:** “Does this match any documented admin/installer workflow?” If not, treat as suspect.

### 4.2. File System & Staging

**Pivot to file activity**
Query `DeviceFileEvents` on the same `DeviceId` **±1h** around the `Timestamp`:
* Look for DLL/EXE/HTA/JS/VBS/SCT/INF/SCR writes in:
    * `C:\Users\<user>\AppData\Local\Temp\`, `%TEMP%`, `%ProgramData%`, desktop, downloads.
    * Browser cache, email attachment folders.
    * UNC paths used in the command line.

**Pay attention to:**
* File written → immediately executed by `rundll32.exe`.
* Files deleted shortly after execution.
* ADS patterns: `filename.ext:stream.dll`.

**Hash & signer**
* Confirm whether the loaded DLL/EXE is signed by Microsoft or a vendor used in your estate.
* Unsigned or oddly signed DLL in a user path → **strong signal**.

### 4.3. Network & C2 Behaviour

**Network pivots**
Query `DeviceNetworkEvents` on same device **±1h**:
* New outbound connections around the time of `rundll32.exe` execution.
* URLs embedded in the `ProcessCommandLine` (especially for `PhotoViewer`/`shimgvw`/`url.dll` cases).

**Red flags:**
* First-seen domains, odd TLDs, IP literals.
* Non-standard ports (e.g., 8080, 8443, 53, 443 to bare IP addresses).
* Beacons starting right after `rundll32` runs.

**Lateral movement hints**
* SMB/UNC paths in the command may indicate lateral staging:
    * UNC shares under user profiles or temp on other hosts.
    * Repeated hits across multiple devices executing from the same share.

### 4.4. Identity, Scope & Blast Radius

**User and role**
* Identify the role of `AccountName` / `InitiatingProcessAccountName`:
    * Workstation user vs. server service account vs. admin.
    * If `IsHighRiskUser == true`, treat as **priority**.

**Check for:**
* Multiple suspicious `rundll32.exe` invocations under the same user.
* Other anomalies in the same timeframe (suspicious sign-ins, MFA fatigue, password reset activity).

**Spread across estate**
* Search for the same `ProcessCommandLine` or DLL path across `DeviceProcessEvents`.
* If you see identical patterns on multiple hosts, treat as a **campaign**, not a single host problem.

---

## 5. Baselining, Tuning & Operational Use

To keep this rule stable in production:

### Baseline first (14–30 days)

Run the query without alerting and export legitimate hits:
* Common helper DLLs, exports, and paths used by your software.
* Routine installer / updater behaviour that legitimately uses `rundll32.exe`.

**Add those to:**
* `AllowedParents` (if you have custom management tools).
* Additional allow conditions on specific, known-good command lines or paths.

### Tight, specific allows only

Never blanket-allow on:
* “Any `rundll32` from `C:\Program Files\`.”
* “Any `rundll32` with `PhotoViewer.dll`.”
* Instead, allow **exact export** + **exact known path** + **signer** where possible.

### Rule deployment pattern

Start as a scheduled hunt surfaced to L2/L3 only.
After tuning, move to an analytic rule that:
* **Raises a high-severity alert** when:
    * `IsHighRiskUser == true`, or
    * `SuspiciousCategory` in ("Scriptlet / HTML application via mshtml",
        "DLL from NTFS alternate data stream",
        "Setupapi INF execution / AWL bypass",
        "Photo viewer DLL download to cache",
        "Zipfldr RouteTheCall proxy EXE execution").
* **Keeps other categories as medium/low** for manual review.

### Incident handling shorthand

* **True positive likely when:**
    * Unusual parent (Office, browser, mail, script host) **AND**
    * user-writable or UNC path **AND**
    * non-Microsoft, unsigned payload **AND**
    * new outbound network activity.
* **Benign more likely when:**
    * Parent is a well-known installer/patcher/updater,
    * helper DLL is vendor-specific,
    * and the pattern is stable across your baseline window.

This single rule gives you broad coverage of modern `rundll32` LOLBAS tradecraft while staying lean enough to live as a production analytic in MDE/Sentinel with minimal noise once baseline tuning is done.
