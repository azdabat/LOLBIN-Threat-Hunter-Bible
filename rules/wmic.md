# wmic.exe LOLBIN Detection (L2/L3 – Production)

## 1. Threat Overview

wmic.exe is a legitimate Windows binary. In modern intrusion tradecraft it is abused to move
execution into a signed, trusted process. This evades naïve allow‑lists and simplistic EDR rules.

Abuse patterns for wmic.exe in the last few years include:

- Use as a downloader or loader as part of phishing and web‑delivered chains.
- Execution with rare or clearly user‑facing parent processes (Office, browser, mail clients).
- Obfuscated or encoded command lines designed to hide payloads and infrastructure.
- Use in mid‑chain stages (post‑initial access, pre‑lateral movement) rather than at the edges.

Effective detection focuses on **context and behaviour**, not on treating wmic.exe as inherently malicious.

## 2. MITRE ATT&CK Techniques

- T1021 Remote Services
- T1077 Windows Admin Shares
- T1082 System Information Discovery
- T1016 System Network Configuration Discovery

## 3. Advanced Hunting Query (MDE)

The following query is written for Microsoft Defender for Endpoint Advanced Hunting
and is designed to be used either interactively or as the basis for a scheduled rule.

```kql
let lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "wmic.exe"
| extend ParentImage = tostring(InitiatingProcessFileName),
         ParentCmd   = tostring(InitiatingProcessCommandLine),
         Cmd         = tostring(ProcessCommandLine)
| where ParentImage !in (AllowedParents)
    or Cmd has_any ("http:", "https:", ".hta", ".js", ".vbs", ".ps1", ".dll", "-enc", "FromBase64String")
| extend SuspiciousReason = case(
    Cmd has_any ("http:", "https:"), "Remote URL / download usage",
    Cmd has_any (".hta",".js",".vbs",".ps1"), "Script content or loader behaviour",
    Cmd has_any ("-enc","FromBase64String"), "Encoded or in‑memory payload",
    true, "Anomalous parent or rare invocation"
  )
| extend PrivilegedAccount = iif(AccountName in (HighRiskAccounts), "Yes", "No")
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

## 4. L3 Pivot Strategy

Once a hit is generated:

1. **Expand process context**
   - Query `DeviceProcessEvents` for the same `DeviceId` and `ReportId`.
   - Build an execution graph: parent → wmic.exe → children.
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

- Capture **all legitimate** wmic.exe usage for at least 14–30 days.
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
