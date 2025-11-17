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

## 4. L3 Pivot Strategy

Once a hit is generated:

1. **Expand process context**
   - Query `DeviceProcessEvents` for the same `DeviceId` and `ReportId`.
   - Build an execution graph: parent → powershell.exe → children.
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

- Capture **all legitimate** powershell.exe usage for at least 14–30 days.
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
