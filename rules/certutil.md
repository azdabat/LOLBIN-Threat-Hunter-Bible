# bitsadmin.exe LOLBIN Detection

## 1. Threat Overview

`bitsadmin.exe` is the legacy CLI for the Background Intelligent Transfer Service (BITS). It is deprecated but still shipped on many Windows versions, and heavily abused as a LOLBIN for:

- **Stealthy payload downloaders/loaders** over HTTP/HTTPS/FTP.
- **Persistence via BITS jobs** that execute a command (`/SetNotifyCmdLine`) after transfers complete.
- **Defense evasion & clean-up** by deleting droppers and logs once a job finishes.
- **Alternate Data Stream (ADS) abuse** and “fileless-ish” execution patterns.
- **Initial access & ransomware staging** (IABs, ransomware crews, and phishing campaigns using BITS to pull second-stage payloads).

Key abuse patterns for `bitsadmin.exe` in recent years:

- Jobs created from user-facing parents (Office, browsers, mail clients, helpdesk tools).
- Download commands with suspicious URLs, odd TLDs, or first-seen infrastructure.
- Encoded or obfuscated command lines (`-enc`, base64, long random paths).
- `/create` + `/addfile` + `/SetNotifyCmdLine` chains creating long-lived, auto-executing jobs.
- Transfer targets or destinations in user-writable paths, temp folders, or ADS.

Detection must treat **`bitsadmin.exe` as suspicious by behaviour and context**, not as universally malicious.

---

## 2. MITRE ATT&CK Techniques

1. Threat Overview
certutil.exe is a legitimate Windows binary frequently abused by threat actors to execute malicious operations within a trusted process context. This technique evades basic allow-lists and simplistic EDR detection rules.

Common abuse patterns include:
- Downloading or loading malicious payloads in phishing and web-delivered attack chains
- Execution from uncommon or user-facing parent processes (Office applications, browsers, email clients)
- Obfuscated command lines hiding payloads and infrastructure details
- Usage in mid-chain attack stages (post-initial access, pre-lateral movement)

Effective detection requires behavioral analysis and contextual awareness rather than treating certutil.exe as inherently malicious.

2. MITRE ATT&CK Techniques
T1105: Ingress Tool Transfer
T1027: Obfuscated Files or Information
T1059: Command and Scripting Interpreter

3. Advanced Hunting Query (MDE/Sentinel)
---

## 3. Advanced Hunting Query (MDE – L3 Rule Core)

The query below is written for **Microsoft Defender for Endpoint – Advanced Hunting**.  
Use it as:

- An **interactive L3 hunt** (broad lookback, analyst-driven pivots), or  
- The core of a **scheduled detection rule** with tuned allow-lists.

```kql
// ======================================================================
// bitsadmin.exe LOLBIN Detection (L3 – Production)
// Author: Ala Dabat
// Scope: Microsoft Defender for Endpoint (DeviceProcessEvents)
// Goal: Catch suspicious downloader / persistence / ADS / exfil abuse
// ======================================================================

// Description: Detect suspicious certutil.exe activity using known LOLBin patterns from sources like LOLBAS
// Focuses on native Windows binaries abuse while excluding CTI-specific indicators
CertUtil LOLBin Detection (L2/L3 - Production)


let lookback = 7d
let HighRiskAccounts = dynamic(["Administrator", "SYSTEM", "NT AUTHORITY\\SYSTEM"]);
let AllowedParents = dynamic(["explorer.exe", "svchost.exe", "msiexec.exe", "mmc.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "certutil.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         ParentCmd = tostring(InitiatingProcessCommandLine),
         Cmd = tostring(ProcessCommandLine)
| where ParentImage !in~ (AllowedParents)
    or Cmd has_any ("http", "https", ".hta", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".dll", "-encode", "-decode", "FromBase64String", "ToBase64String", "decode", "encode", "urlcache", "faultrep.dll")
| extend SuspiciousReason = case(
    Cmd contains "http" or Cmd contains "https", "Remote resource retrieval",
    Cmd has_any (".hta", ".js", ".jse", ".vbs", ".vbe", ".ps1"), "Script file interaction",
    Cmd has_any ("-encode", "-decode", "FromBase64String", "ToBase64String"), "Encoding/decoding activity",
    Cmd has_any ("urlcache", "faultrep.dll"), "Alternative data stream or DLL abuse",
    "Unusual parent process or invocation pattern"
  )
| extend PrivilegedAccount = iff(AccountName in~ (HighRiskAccounts), "Yes", "No")
| project Timestamp, DeviceId, DeviceName, AccountName, PrivilegedAccount,
          FileName, ProcessCommandLine = Cmd, ParentImage, ParentCmd, InitiatingProcessAccountName,
          ReportId, SuspiciousReason
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
   - Build an execution graph: parent → certutil.exe → children.
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

- Capture **all legitimate** certutil.exe usage for at least 14–30 days.
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
