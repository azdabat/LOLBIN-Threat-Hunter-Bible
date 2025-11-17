# bitsadmin.exe LOLBIN Detection (L3 – Production)

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

Primary:

- **T1197 – BITS Jobs** (download, execute, clean-up via BITS jobs)
- **T1105 – Ingress Tool Transfer / Remote File Copy**
- **T1071 – Application Layer Protocol** (HTTP/HTTPS command & control / staging)
- **T1564.004 – Hide Artifacts: NTFS Alternate Data Streams**
- **T1053.005 – Scheduled Task / Job (BITS-like job scheduling for persistence)**

Supporting (depending on usage):

- **T1560 – Archive Collected Data** (if pulling/staging archives)
- **T1567 – Exfiltration over Web Services** (BITS upload jobs)
- **T1070 – Indicator Removal on Host** (using BITS to remove artefacts post-execution)

---

## 3. Advanced Hunting Query (MDE – L3 Rule Core)

The query below is written for **Microsoft Defender for Endpoint – Advanced Hunting**.  
Use it as:

- An **interactive L3 hunt** (broad lookback, analyst-driven pivots), or  
- The core of a **scheduled detection rule** with tuned allow-lists.

```kql
// ======================================================================
// bitsadmin.exe LOLBIN Detection (L3 – Production)
// Author: Ala Dabat (Alstrum)
// Scope: Microsoft Defender for Endpoint (DeviceProcessEvents)
// Goal: Catch suspicious downloader / persistence / ADS / exfil abuse
// ======================================================================

let lookback = 7d;

// -------------------------------------------
// Tunables – adapt to your environment
// -------------------------------------------

// Parents that commonly/legitimately spawn bitsadmin in your org
let AllowedParents = dynamic([
    "explorer.exe",
    "svchost.exe",
    "services.exe"
]);

// High-value or admin accounts (expand per org)
let HighValueAccounts = dynamic([
    "Administrator",
    "Domain Admin",
    "Enterprise Admin"
]);

// Behavioural tokens
let DownloadTokens    = dynamic(["http://","https://","ftp://"]);
let ScriptTokens      = dynamic([".ps1",".vbs",".js",".hta","wscript","cscript","powershell"]);
let EncodingTokens    = dynamic([" -enc ","-EncodedCommand","FromBase64String"]);
let PersistenceTokens = dynamic(["/SetNotifyCmdLine","/setnotifycmdline"," /create "," /addfile "," /resume "," /complete "]);
let ADSTokens         = dynamic([":Zone.Identifier",":$DATA",":hidden"]);
let UploadTokens      = dynamic([" /upload ","/UPLOAD "]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "bitsadmin.exe"
// Normalise core fields
| extend
    ParentImage = tostring(InitiatingProcessFileName),
    ParentCmd   = tostring(InitiatingProcessCommandLine),
    Cmd         = tostring(ProcessCommandLine),
    Account     = tostring(AccountName)
// Behaviour flags
| extend
    HasDownload    = Cmd has_any (DownloadTokens),
    HasScript      = Cmd has_any (ScriptTokens),
    HasEncoding    = Cmd has_any (EncodingTokens),
    HasPersistence = Cmd has_any (PersistenceTokens),
    HasADS         = Cmd has_any (ADSTokens),
    HasUpload      = Cmd has_any (UploadTokens),
    IsRareParent   = iif(ParentImage !in (AllowedParents), 1, 0),
    IsPrivAccount  = iif(Account in (HighValueAccounts), 1, 0)
// Simple risk scoring – tune thresholds in rules
| extend RiskScore =
    0
    + 2 * todouble(HasDownload)
    + 2 * todouble(HasPersistence)
    + 2 * todouble(HasEncoding)
    + 1 * todouble(HasScript)
    + 1 * todouble(HasADS)
    + 1 * todouble(HasUpload)
    + 1 * todouble(IsRareParent)
    + 1 * todouble(IsPrivAccount)
// Detection tier
| extend DetectionTier = case(
    RiskScore >= 7, "High",
    RiskScore >= 4, "Medium",
    "Low"
)
// Analyst-facing justification
| extend SuspiciousReason = case(
    HasDownload and HasPersistence and IsRareParent == 1,
        "BITS job created from rare parent with URL + persistence (notify cmdline)",
    HasDownload and HasEncoding,
        "BITS used as encoded downloader (URL + encoding)",
    HasDownload and HasScript,
        "BITS downloading script or loader content",
    HasADS,
        "BITS referencing NTFS alternate data streams",
    HasUpload,
        "BITS used for possible data upload / exfiltration",
    IsRareParent == 1,
        "bitsadmin.exe spawned from rare or user-facing parent",
    IsPrivAccount == 1,
        "bitsadmin.exe executed under high-value account",
    true,
        "Unusual bitsadmin.exe usage – review in context"
)
// Inline hunter directives – can be surfaced in the alert description
| extend HuntingDirectives = case(
    DetectionTier == "High",
        "Treat as likely malicious. Isolate host, capture triage package, pivot to DeviceFileEvents and DeviceNetworkEvents +/- 2h. Extract URLs, hashes, and child processes; check for persistence via BITS jobs and scheduled tasks; escalate as incident if any payload execution or ransomware staging is observed.",
    DetectionTier == "Medium",
        "Review full process tree (parent + children), then pivot to DeviceFileEvents and DeviceNetworkEvents. Validate URL/domain against CTI and reputation. If infrastructure is first-seen or risky, scope for other hosts and users, and consider containment.",
    // Low tier
        "Baseline this usage. Confirm whether this is part of known admin tooling or software update workflows. If benign, document and consider adding a scoped allow-pattern for this exact parent + command structure."
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FileName,
    Cmd,
    ParentImage,
    ParentCmd,
    AccountName = Account,
    InitiatingProcessAccountName,
    DetectionTier,
    RiskScore,
    SuspiciousReason,
    HuntingDirectives,
    HasDownload,
    HasPersistence,
    HasEncoding,
    HasScript,
    HasADS,
    HasUpload,
    IsRareParent,
    IsPrivAccount,
    ReportId
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
