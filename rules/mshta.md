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
- Surfaces privileged accounts separately for accelerated triage.

## 4. L3 Pivot Strategy

Once a hit is generated:

1. **Expand process context**
   - Query `DeviceProcessEvents` for the same `DeviceId` and `ReportId`.
   - Build an execution graph: parent → mshta.exe → children.
   - Identify whether any downstream processes are clearly malicious (dumpers, tunnellers, archivers, RDP tools).

2. **File system activity**
   - Pivot into `DeviceFileEvents` for the same host ±1 hour.
   - Look for:
     - Newly‑written EXE/DLL/PS1/VBS/JS in user profile, temp, ProgramData.
     - Files executed shortly after being written.

3. **Network behaviour**
   - Pivot into `DeviceNetworkEvents` using the same time window.
   - Extract remote IPs, domains, ports and correlate with CTI.
   - Pay particular attention to first‑seen infrastructure and unusual TLDs.

4. **Identity and scope**
   - Identify the user and business role.
   - Check whether this account has other anomalies (Azure sign‑ins, MFA fatigue, risky sign‑ins).

## 5. Baselining and Suppression

To keep this rule production‑safe:

- Capture **all legitimate** mshta.exe usage for at least 14–30 days.
- Document:
  - Parents,
  - Command lines,
  - Typical times and hosts.
- Create **tight** allow‑patterns, never wildcards across full command lines.
- Re‑validate baselines after:
  - Major software rollouts,
  - Tooling changes,
  - Admin process changes.

## 6. CTI / MISP / OpenCTI Integration

For confirmed malicious instances:

- Extract:
  - File hashes of payloads and staging artefacts.
  - Domains, IPs, URIs observed in network connections.
- Push to MISP/OpenCTI as:
  - Attributes on existing intrusion sets where appropriate.
  - New events where this represents a new cluster or campaign.
- Tag events with:
  - Confidence level,
  - Kill‑chain phase,
  - Detection source (LOLBIN MDE rule, Sentinel analytic).

This turns a single host‑level detection into durable intelligence.
