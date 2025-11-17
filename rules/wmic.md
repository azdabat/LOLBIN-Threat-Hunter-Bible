# wmic.exe LOLBIN Detection (L2/L3 – Production)
Author: Ala Dabat

---

## 1. Threat Overview
`wmic.exe` provides WMI command-line access. Attackers abuse it to:
- Execute remote commands (`wmic /node:<host> process call create`)
- Spawn PowerShell/HTA/script payloads
- Enumerate system/network info before lateral movement
- Perform admin share checks, service manipulation, or discovery

This rule flags **abnormal usage**, unusual parents, script/encoded loaders, lateral movement patterns, and remote WMI execution—not legitimate admin tasks.

---

## 2. MITRE ATT&CK
- **T1021 – Remote Services (WMI)**
- **T1077 – Windows Admin Shares**
- **T1082 – System Information Discovery**
- **T1016 – Network Configuration Discovery**

---

## 3. Advanced Hunting Query (Compact Native Rule)

```kql
// ========================================================================
// LOLBIN: wmic.exe – Suspicious Usage (Low Noise)
// Author: Ala Dabat
// Table: DeviceProcessEvents
// ========================================================================
let lookback = 7d;
let HighRisk = dynamic(["Administrator","SYSTEM","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "wmic.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         lcmd = tolower(Cmd)
// Suspicious conditions: remote node access, script proxies, encoded payloads, odd parents
| where ParentImage !in (AllowedParents)
   or lcmd has "/node:"                          // remote WMI exec
   or lcmd has_any ("process","call","create")    // often used to spawn payloads
   or lcmd has_any ("powershell","cmd /c","wscript","mshta","rundll32")
   or lcmd has_any (".ps1",".js",".vbs",".hta","-enc","frombase64string")
   or lcmd has_any ("http://","https://")
| extend Reason =
    case(
        lcmd has "/node:",                        "Remote WMI execution",
        lcmd has_any ("process","call","create"), "WMI process execution",
        lcmd has_any ("powershell","mshta","wscript","rundll32"), "Proxy execution via wmic",
        lcmd has_any (".ps1",".js",".vbs",".hta"), "Script payload via WMI",
        lcmd has_any ("-enc","frombase64string"),  "Encoded loader/command",
        lcmd has_any ("http://","https://"),       "URL-based remote staging",
        ParentImage !in (AllowedParents),          "Unexpected parent",
        true,                                      "Rare wmic usage"
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
`parent` → **`wmic.exe`** → (payload)

**Red flags:**
* **Parent:** Office application, web browser, mail client, `mshta`, `wscript`.
* **Child:** `PowerShell`, `cmd`, `rundll32`, script engines (all indicate execution proxy).
* **Remote Usage:** Remote WMI (`/node:`) calls followed immediately by lateral movement or service changes.

### 4.2. File & Staging Activity

Pivot to `DeviceFileEvents` **±1h**:

* **Staging:** Look for payload writes in `TEMP`/`AppData`/`ProgramData`.
* **Timing:** Dropped PS1/VBS/JS/EXE shortly **before** a `wmic process call create` execution.
* **Signer:** Unsigned binaries or scriptlets executed right after staging.

### 4.3. Network & Remote Ops

Check `DeviceNetworkEvents`:

* **Lateral Movement:** Connections to internal lateral movement targets.
* **Protocol:** SMB/ADMIN$ usage, WMI RPC traffic (port 135 and dynamic ports).
* **C2:** New outbound infrastructure detected after WMI execution (indicates payload delivery or C2).

### 4.4. Identity, Privilege & Spread

* **Prioritize:** Escalate immediately if **`Privileged == Yes`**.
* **Scope Check:**
    * Look for multiple `/node:` executions across different hosts.
    * Check if the same user is performing sequential remote WMI operations.
    * Look for adjacent alerts involving other lateral movement tools (`psexec`, `wmic`, `sc.exe`, or `winrm`).

---

## 5. Baselining & Suppression

* **Observe:** Record legitimate admin automation for 2–4 weeks.
* **Allow:**
    * Known good remote inventory scripts.
    * Vendor monitoring tools using WMI queries.
* **Warning:** Never broadly allow process creation (`wmic process call create`) via WMI.

### Severity Guidance:

* **High:** Remote WMI execution (`/node:`) or script/encoded payloads.
* **Medium:** WMI spawning `PowerShell`/`cmd`.
* **Low:** Simple queries (`wmic os get /value`) with expected parents.

## 6. Operational Notes

This rule has no Threat Intelligence (TI) dependencies.

It catches real-world **lateral movement**, **remote execution**, discovery, and **proxy execution** via WMI, while staying low-noise once baselined for legitimate use.
