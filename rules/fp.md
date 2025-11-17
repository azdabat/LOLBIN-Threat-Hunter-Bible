# fp.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`fp.exe` (FrontPage/FrontPage Server Extensions binary) is rarely used legitimately today.  
Attackers abuse it as a stealthy proxy to:
- Execute commands through legacy COM/MSI interfaces  
- Load/launch payloads from TEMP/AppData/user-writable paths  
- Read or write files during staging  
- Execute secondary LOLBINs (cmd, powershell, rundll32)

Because almost no environment uses FrontPage tooling anymore, **any fp.exe activity is high-signal unless tied to a known legacy workflow**.

---

## 2. MITRE ATT&CK
- **T1005 – Data from Local System**  
- Often overlaps with: proxy execution (T1218), discovery, staging, and initial payload loading.

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: fp.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let lookback = 7d;
let HighRisk = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "fp.exe"
| extend Parent = tostring(InitiatingProcessFileName),
         Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         lcmd = tolower(Cmd)
// Suspicious: scripts, encoded payloads, URL fetches, proxy chains, writable paths
| where Parent !in (AllowedParents)
   or lcmd has_any (".vbs",".js",".hta",".ps1","-enc","frombase64string")
   or lcmd has_any ("cmd","powershell","rundll32","mshta","cscript","wscript")
   or lcmd has_any ("http://","https://")
   or lcmd has_any (":\\users\\","\\appdata\\","\\temp\\",":\\programdata\\")
| extend Reason =
    case(
        lcmd has_any ("-enc","frombase64string"), "Encoded loader",
        lcmd has_any (".js",".vbs",".hta",".ps1"), "Script payload via fp.exe",
        lcmd has_any ("cmd","powershell","rundll32"), "Proxy execution chain",
        lcmd has_any ("http://","https://"), "Remote fetch",
        lcmd has_any (":\\users\\","\\appdata\\","\\temp\\"), "User-writable payload",
        Parent !in (AllowedParents), "Unexpected parent",
        true, "Rare fp.exe invocation"
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
`parent` → **`fp.exe`** → `payload`

**High-signal indicators:**
* **Parent:** Office application, browser, mail client, script host.
* **Child:** `PowerShell`, `cmd`, `rundll32`, `mshta`, `cscript`/`wscript` (indicates execution proxy).
* **Payload:** `fp.exe` launching **unsigned binaries** from `TEMP`/`AppData`.

### 4.2. File Activity

Check `DeviceFileEvents` **±1h**:

* **Staging:** Payloads created under `%TEMP%`, `%AppData%`, `%ProgramData%`.
* **Timing:** `fp.exe` reading/writing files shortly before an EXE/PS1/JS is launched.
* **Anti-forensics:** Files deleted immediately after execution.

### 4.3. Network Behaviour

Pivot to `DeviceNetworkEvents`:

* **Traffic:** Outbound connections right after `fp.exe` runs.
* **Infrastructure:** New domains, bare IPs, non-standard ports.
* **Warning:** `fp.exe` rarely touches the network → **any network activity is suspicious**.

### 4.4. Identity & Spread

* **Prioritize:** Escalate immediately if **`Privileged == Yes`**.
* **Investigate:**
    * Multiple hosts triggering `fp.exe`.
    * Same user executing different LOLBINs in short succession.
    * Adjacent alerts involving `rundll32`, `wscript`, `mshta`, or `schtasks`.

---

## 5. Baselining & Suppression

* **Record:** 14–30 days of usage (expected to be **normally zero**).
* **Allow only:**
    * Known legacy FrontPage tooling (if still in use).
    * Documented vendor maintenance scripts.
* **Warning:** Never wildcard-allow `fp.exe`.

### Severity Suggestions:

* **High:** Payload execution, encoded commands, remote fetch.
* **Medium:** Proxy chains (`fp.exe` → `cmd`/`ps`).
* **Low:** Benign read-only enumeration from expected parents (rare).

---

## 6. Operational Notes

This is a standalone production rule—no Threat Intelligence (TI) dependencies.

It focuses on real tradecraft where `fp.exe` is used as a **stealth launcher** or **file-iteration execution proxy**, without flagging standard cleanup or maintenance routines.
