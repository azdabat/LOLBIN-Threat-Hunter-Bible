# wscript.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`wscript.exe` runs Windows Script Host payloads (VBS/JS). Attackers frequently abuse it for:
- Dropping or executing staged payloads via JS/VBS/HTA
- Download cradle activity using msxml/http objects
- Mid-chain loaders after phishing documents or browser exploitation
- Obfuscated, encoded or base64-wrapped execution
- Proxy execution for PowerShell, rundll32, cmd, mshta

This rule focuses on abnormal usage patterns—not legitimate system or admin scripts.

---

## 2. MITRE ATT&CK
- **T1059 – Command & Scripting Interpreter**
- **T1204 – User Execution**

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: wscript.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let lookback = 7d;
let HighRisk = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","services.exe","svchost.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "wscript.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         lcmd = tolower(Cmd)
// Suspicious: script proxies, downloaders, encoded payloads, odd parents
| where ParentImage !in (AllowedParents)
   or lcmd has_any (".vbs",".js",".jse",".vbe",".wsf",".hta")
   or lcmd has_any ("powershell","cmd /c","mshta","rundll32","cscript")
   or lcmd has_any ("http://","https://")
   or lcmd has_any ("-enc","frombase64string")
   or lcmd has_any (":\\users\\",":\\programdata\\","\\appdata\\","\\temp\\")
| extend Reason =
    case(
        lcmd has_any (".vbs",".js",".hta",".wsf"),         "Script payload",
        lcmd has_any ("http://","https://"),               "URL-based loader",
        lcmd has_any ("-enc","frombase64string"),          "Encoded execution",
        lcmd has_any ("powershell","mshta","rundll32"),    "Proxy chain from wscript",
        lcmd has_any (":\\users\\",":\\programdata\\"),    "Payload in user-writable path",
        ParentImage !in (AllowedParents),                  "Unexpected parent",
        true,                                              "Rare wscript usage"
    )
| extend Privileged = iif(AccountName in (HighRisk),"Yes","No")
| project Timestamp, DeviceId, DeviceName, AccountName, Privileged,
          FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, Reason, ReportId
| order by Timestamp desc
```
## 4. Hunter Directives & L3 Pivot Strategy

### 4.1. Process Chain

Rebuild the execution context around the hit:
`parent` → **`wscript.exe / cscript.exe`** → `payload`

**Key flags:**
* **Parent:** Office application, browser, mail client, `mshta`, `cmd`.
* **Child:** `PowerShell`, `rundll32`, `curl`, `certutil`, `mshta` (indicates execution proxy or further staging).
* **Payload:** `wscript` spawning encoded PS1 or fetching remote JS/VBS payloads via URLs.

### 4.2. File Activity (DeviceFileEvents)

Check **±1h** around the event for:

* **Staging:** New JS/VBS/JSE/WSF drops in high-risk directories (`TEMP`/`AppData`/`ProgramData`).
* **Timing:** Payloads written to disk and then **immediately executed**.
* **Source:** Unsigned or unusual scripts found in email attachment folders or `Downloads` directories.

### 4.3. Network Activity

Pivot to `DeviceNetworkEvents`:

* **Traffic:** Outbound network traffic immediately following execution.
* **Infrastructure:** New domains, bare IPs, or odd ports.
* **Indicators:** Connections that strongly suggest command download or staging.

### 4.4. Identity & Scope

* **Prioritize:** Escalate immediately if **`Privileged == Yes`**.
* **Scope Check:**
    * See if the same user launched multiple script payloads.
    * Check for lateral spread of similar `wscript` command lines across endpoints.
    * Determine if the pattern aligns with a **phishing** campaign (e.g., initial script loader → PS/Rundll chain).

---

## 5. Baselining & Suppression

* **Capture:** Record normal scripting tasks for 2–4 weeks.
* **Legitimate Cases often include:**
    * Enterprise login scripts.
    * Vendor installers.
    * IT automation (with known paths/parents).
* **Warning:** Never blanket-allow based on file extension alone.

### Severity Guidance:

* **High:** Encoded loaders, URL-based scripts, `wscript` → PS chain.
* **Medium:** Proxy execution with odd parents.
* **Low:** Admin scripts with stable baselines.

## 6. Operational Notes

This is a standalone production rule—no Threat Intelligence (TI) dependencies required.

It focuses on real tradecraft: **script loader abuse**, encoded payloads, **phishing-stage execution**, and cross-LOLBIN chains (`wscript` → `mshta` → `PowerShell`).
