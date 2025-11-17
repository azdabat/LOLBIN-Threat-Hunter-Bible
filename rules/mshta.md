# mshta.exe LOLBIN Detection (L3 – Production, Native)
Author: Ala Dabat

## 1. Threat Overview
mshta.exe executes HTML Applications (HTA) and scriptlets. Attackers abuse it to load remote HTA, JS, VBS, and SCT payloads; execute fileless inline commands; bypass AppLocker allow-listing; trigger chained LOLBIN activity (mshta → powershell/cscript); and execute under rare parents such as Office, browsers, RMM tools, and scheduled tasks. Detection focuses on command content, URL usage, parent process, and writable-path behaviours.

## 2. MITRE Mapping
- T1218.005 – Signed Binary Proxy Execution (mshta)
- T1059 – JScript/VBScript Interpreter
- T1204 – User Execution

## 3. Advanced Hunting Query (Compact, Native MDE)

```kql
// mshta.exe LOLBIN Detection (L3 – Production, Native)
// Author: Ala Dabat

let lookback=7d;
let AllowedParents=dynamic(["explorer.exe","cmd.exe","powershell.exe","pwsh.exe","svchost.exe"]);
let HighValueAcc=dynamic(["Administrator","Domain Admin","Enterprise Admin"]);
let UrlTokens=dynamic(["http://","https://"]);
let ScriptTokens=dynamic([".hta",".js",".vbs",".sct"]);
let EncTokens=dynamic(["-enc","FromBase64String"]);
let WriteTokens=dynamic(["\\AppData\\","\\Temp\\","\\ProgramData\\","\\Users\\"]);

DeviceProcessEvents
| where Timestamp>=ago(lookback)
| where FileName =~ "mshta.exe"
| extend ParentImage=tostring(InitiatingProcessFileName),ParentCmd=tostring(InitiatingProcessCommandLine),Cmd=tostring(ProcessCommandLine),Acc=tostring(AccountName)
| extend HasUrl=Cmd has_any(UrlTokens),HasScript=Cmd has_any(ScriptTokens),HasEnc=Cmd has_any(EncTokens),HasWrite=Cmd has_any(WriteTokens),RareParent=iif(ParentImage !in (AllowedParents),1,0),Priv=iif(Acc in (HighValueAcc),1,0)
| extend RiskScore=0+3*todouble(HasUrl)+3*todouble(HasScript)+2*todouble(HasEnc)+1*todouble(HasWrite)+1*todouble(RareParent)+1*todouble(Priv)
| extend DetectionTier=case(RiskScore>=7,"High",RiskScore>=4,"Medium","Low")
| extend SuspiciousReason=case(
    HasUrl and HasScript,"Remote HTA/script loading",
    HasEnc,"Encoded or obfuscated execution",
    HasScript and RareParent==1,"Script payload from rare parent",
    RareParent==1,"mshta launched from rare parent",
    Priv==1,"Privileged account executing mshta",
    "Unusual mshta behaviour"
)
| extend HuntingDirectives=case(
    DetectionTier=="High","Isolate host, reconstruct process chain, inspect HTA/JS/VBS/SCT, pivot FileEvents+NetworkEvents, find chained LOLBINs, scope lateral hosts.",
    DetectionTier=="Medium","Validate parent, domain, user role; check internal vs external; compare patterns; escalate if repeating.",
    "Baseline candidate; confirm with owners if recurring."
)
| project Timestamp,DeviceId,DeviceName,FileName,Cmd,ParentImage,ParentCmd,AccountName=Acc,InitiatingProcessAccountName,DetectionTier,RiskScore,SuspiciousReason,HuntingDirectives,HasUrl,HasScript,HasEnc,HasWrite,RareParent,Priv,ReportId
| order by Timestamp desc

```

Key properties:

- Leverages `InitiatingProcessFileName` and `ProcessCommandLine` for context.
- Treats rare parents and encoded / network‑touching commands as primary signal.
- Provides a `SuspiciousReason` column to explain why the row is interesting.
## 4. Hunter Directives & L3 Pivot Strategy

Use **DetectionTier** + **SuspiciousReason** to decide escalation.

### 4.1. High – Likely Malicious (Immediate Action)

**Typical Patterns:**
* `mshta http://host/payload.hta` → remote HTA loader
* `mshta https://host/payload.js` → script execution
* `mshta vbscript:Execute("...")` → inline fileless execution
* `mshta` launched by Office, browsers, RMM, scheduled tasks, helpdesk tools

**Actions – Containment:**
* **Isolate device** when:
    * Remote script execution is confirmed.
    * `mshta` spawns `powershell`/`cscript`.
    * Obfuscated or encoded payload chains are found.

**Process Tree Reconstruction:**
* Re-run `DeviceProcessEvents` **±2h**.
* Look for children:
    * `powershell.exe`, `pwsh.exe`
    * `wscript.exe`, `cscript.exe`
    * `rundll32.exe`, `regsvr32.exe`
    * Archive loaders or encryption tools

**File Analysis:**
* Identify HTA/JS/VBS/SCT files.
* Inspect creation timestamp vs. execution time.
* Check writable paths (`AppData`, `Temp`, `ProgramData`).

**Network & Scope:**
* Review connections originating from `mshta`.
* Identify domains/IPs/TLD patterns.
* Check other hosts for the same URL/path.

**Impact Assessment:**
* Determine the payload executed.
* Determine if multiple endpoints hit the same host.
* Assess lateral movement or chained LOLBIN usage.

### 4.2. Medium – Suspicious but Possibly Legitimate

**Typical Patterns:**
* Internal HTA files.
* Local application components using `mshta`.
* Rare parent but benign paths.

**Actions:**
* Validate parent process (admin script vs. Office application).
* Validate domain/URL is internal and expected.
* Compare with patterns across the estate.
* Review `mshta` children and follow-up alerts.
* Recurring and benign → **baseline**.
* Unclear → track and escalate if repeated.

### 4.3. Low – Baseline Candidate / Watch-List

**Typical Patterns:**
* `mshta` invoked by internal legacy tools.
* Non-suspicious local HTA usage.
* Rare parent but benign context.

**Actions:**
* Confirm with system/app owners.
* Recurring benign → **baseline**.
* One-off → **watch-list**.

---

## 5. Baselining & Suppression (Low Noise)

### Baseline Legitimate `mshta` Usage (14–30 days):
* Track parent processes.
* HTA/script paths.
* Execution frequency.
* Typical users.
* Device types.

**Identify Known Good Patterns:**
* Corporate VPN/profile installers.
* Internal UI modules executed via HTA.
* Internal IT admin automation.

**Scoped Allow-Patterns:**
* **Never allow `mshta` globally.**
* Use targeted conditions such as:
    `ParentImage == "corpapp.exe" AND Cmd has "C:\\Program Files\\CorpApp\\ui.hta"`
* Scope by:
    * Device groups
    * User roles
    * Known internal directories

---

## 6. CTI / MISP / OpenCTI Integration

For confirmed malicious instances:

* **Extract:**
    * File hashes of payloads and staging artifacts.
    * Domains, IPs, URIs observed in network connections.
* **Push to MISP/OpenCTI as:**
    * Attributes on existing intrusion sets where appropriate.
    * New events where this represents a new cluster or campaign.
* **Tag events with:**
    * Confidence level,
    * Kill-chain phase,
    * Detection source (LOLBIN MDE rule, Sentinel analytic).

This turns a single host-level detection into durable intelligence.
- Surfaces privileged accounts separately for accelerated triage.

