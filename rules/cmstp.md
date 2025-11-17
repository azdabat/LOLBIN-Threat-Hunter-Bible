# cmstp.exe LOLBIN Detection (L3 – Production, Native MDE/Sentinel)

## 1. Threat Overview

`cmstp.exe` (Connection Manager Profile Installer) is a signed Windows binary used to install Connection Manager service profiles from **INF files**. Adversaries abuse it to:

- **Proxy execution of malicious code** via specially crafted `.inf` files (e.g. `RunPreSetupCommandsSection`, `UnregisterOCXSection` with `scrobj.dll` / `.sct` scriptlets).
- **Bypass Application Control / AppLocker** by having a trusted binary load and execute attacker-controlled content (local or remote INF).
- **Bypass UAC** when invoked with particular flags/contexts to gain elevated execution.
- **Execute from user-writable locations or remote shares** (temp, profile folders, UNC/WebDAV paths) instead of legitimate VPN/profile stores.

Detection should focus on **INF path + switches + parent process context**, not on `cmstp.exe` alone.

---

## 2. MITRE ATT&CK Techniques

- **T1218.003 – Signed Binary Proxy Execution: CMSTP**  
  CMSTP used to proxy malicious code execution from INF/scriptlet content.
- **T1059 – Command and Scripting Interpreter**  
  Scriptlets / commands embedded in INF, often invoking `scrobj.dll`, script engines, or PowerShell.
- **T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control**  
  CMSTP leveraged to gain elevated code execution without typical prompts.
- **T1204 – User Execution**  
  User coerced into launching CMSTP via LNK, Office macro, phishing lure, etc.

---

## 3. Advanced Hunting Query (MDE – L3 Rule Core, Native Only)

Use this in **Microsoft Defender for Endpoint – Advanced Hunting**.  
For a low-noise **analytics rule**, filter on `DetectionTier in ("Medium","High")` or `RiskScore >= 4`.

```kql
// ======================================================================
// cmstp.exe LOLBIN Detection (L3 – Production, Native)
// Author: Ala Dabat (Alstrum)
// Scope: Microsoft Defender for Endpoint (DeviceProcessEvents)
// Goal: Catch malicious INF-based proxy execution, AWL/UAC bypass via CMSTP
// ======================================================================

let lookback = 7d;

// -------------------------------------------
// Tunables – adapt to your environment
// -------------------------------------------

// Parents that are *expected* to spawn cmstp.exe in your org (VPN clients, system services)
let AllowedParents = dynamic([
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "rundll32.exe"
]);

// High-value or admin accounts (expand per org)
let HighValueAccounts = dynamic([
    "Administrator",
    "Domain Admin",
    "Enterprise Admin"
]);

// User-writable or suspicious locations for INF files
let UserWriteDirTokens = dynamic([
    "\\Users\\",
    "\\Users\\Public\\",
    "\\AppData\\",
    "\\Temp\\",
    "\\ProgramData\\",
    "Desktop",
    "Downloads"
]);

// Switches commonly used in CMSTP abuse chains
// /s  = silent, /ni = no UI, /ns = no shortcuts, /au = all users
let InfAbuseSwitches = dynamic([
    " /s", "/s ",
    " /ni", "/ni ",
    " /ns", "/ns ",
    " /au", "/au "
]);

// Remote or external paths for INF (UNC, WebDAV, HTTP[S])
let RemotePathTokens = dynamic([
    "http://",
    "https://",
    "\\\\"
]);

// Scriptlet / COM abuse markers
let ScriptletTokens = dynamic([
    ".sct",
    "scrobj.dll"
]);

// DLL/EXE hints sometimes referenced via INF or secondary payloads
let DllExeTokens = dynamic([
    ".dll",
    ".exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "cmstp.exe"
// Normalise fields
| extend
    ParentImage = tostring(InitiatingProcessFileName),
    ParentCmd   = tostring(InitiatingProcessCommandLine),
    Cmd         = tostring(ProcessCommandLine),
    Account     = tostring(AccountName)
// Core behavioural flags
| extend
    HasInf          = Cmd has ".inf",
    HasAbuseSwitch  = Cmd has_any (InfAbuseSwitches),
    HasRemoteInf    = HasInf and Cmd has_any (RemotePathTokens),
    HasUserWriteInf = HasInf and Cmd has_any (UserWriteDirTokens),
    HasScriptlet    = Cmd has_any (ScriptletTokens),
    HasDllExe       = Cmd has_any (DllExeTokens),
    IsRareParent    = iif(ParentImage !in (AllowedParents), 1, 0),
    IsPrivAccount   = iif(Account in (HighValueAccounts), 1, 0)
// Simple risk scoring – tune weights and thresholds for your environment
| extend RiskScore =
      0.0
    + 2.0 * todouble(HasInf)
    + 2.0 * todouble(HasAbuseSwitch)
    + 2.0 * todouble(HasRemoteInf or HasUserWriteInf)
    + 2.0 * todouble(HasScriptlet)
    + 1.0 * todouble(HasDllExe)
    + 1.0 * todouble(IsRareParent)
    + 1.0 * todouble(IsPrivAccount)
// Detection tier based on RiskScore
| extend DetectionTier = case(
    RiskScore >= 7.0, "High",
    RiskScore >= 4.0, "Medium",
    "Low"
)
// Human-readable justification for triage
| extend SuspiciousReason = case(
    HasRemoteInf and HasAbuseSwitch,
        "CMSTP installing remote INF with silent/‘no UI’ switches (likely AWL/UAC bypass).",
    HasUserWriteInf and HasAbuseSwitch,
        "CMSTP installing INF from user-writable path with silent/‘no UI’ switches.",
    HasInf and HasScriptlet,
        "CMSTP INF chain likely executing scriptlets via scrobj.dll/.sct.",
    HasInf and IsRareParent == 1,
        "CMSTP INF install triggered from rare or user-facing parent process.",
    IsRareParent == 1,
        "CMSTP spawned from rare parent process – check for phishing or macro-based launch.",
    IsPrivAccount == 1,
        "CMSTP executed under high-privilege account – elevated impact if malicious.",
    true,
        "Unusual CMSTP usage – review in full process and file context."
)
// Inline L2/L3 hunter directives – can be surfaced in alert description or notebooks
| extend HuntingDirectives = case(
    DetectionTier == "High",
        "Treat as likely malicious. Isolate device if possible. Pull full process tree for this ReportId; inspect the INF file (local or remote) and any referenced scriptlets or DLL/EXE payloads. Pivot to DeviceFileEvents and DeviceNetworkEvents +/- 2h to confirm payload staging, UAC bypass, or persistence, and scope for similar CMSTP patterns across other hosts.",
    DetectionTier == "Medium",
        "Review parent process, INF path, and switches. Confirm whether this matches a known VPN/connection-manager deployment or admin workflow. Pivot to other CMSTP executions with the same INF path or parent, and check recent file creations in user-writable paths. If pattern is new or rare, consider containment and escalate for deeper analysis.",
    // Low tier
        "Baseline CMSTP usage. Check if this aligns with expected VPN profile installations or admin tools. If benign and recurring, document owners and consider adding a tightly scoped allow-pattern for this exact parent + INF path + switch combination."
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
    HasInf,
    HasAbuseSwitch,
    HasRemoteInf,
    HasUserWriteInf,
    HasScriptlet,
    HasDllExe,
    IsRareParent,
    IsPrivAccount,
    ReportId
// For a low-noise analytics rule, you can optionally uncomment:
// | where DetectionTier in ("Medium","High")
| order by Timestamp desc

```

4. Hunter Directives & L3 Pivot Strategy
Use DetectionTier + SuspiciousReason to prioritise.
4.1 High – Likely Malicious (Immediate Action)

Typical patterns:
Remote INF (http[s]:// or UNC) plus silent/no-UI switches.
INF from %TEMP%, user profile, Downloads, or AppData with silent switches.
INF chain referencing .sct / scrobj.dll or other scriptlet markers.
Rare parent (Office, browser, mail client, helpdesk tool, script host) + INF abuse.

Actions:
Containment
Consider isolating the host in MDE if:
Downstream child processes look clearly malicious (script engines, payload runners, encryptors).
Host shows additional suspicious activity (other LOLBINs, lateral movement tools).
Process Tree Reconstruction
Re-run DeviceProcessEvents for the same DeviceId and ReportId (or ±2h window).
Build chain: user/initial process → parent → cmstp.exe → children.

Look for:

Script engines (wscript.exe, cscript.exe, powershell.exe),

Archiving/encryption tools,
RDP/remote-access tooling,
Other LOLBINs (regsvr32.exe, rundll32.exe, mshta.exe).
INF & Payload Inspection
Identify the INF path from Cmd (local file, UNC, or URL).

Retrieve the INF file content where possible and inspect:

RunPreSetupCommandsSection,
UnregisterOCXSection,
Any scriptlet or binary execution directives.
Map any referenced .sct, .dll, or .exe payloads and locate them on disk.

File & Persistence Check
Pivot to DeviceFileEvents (same DeviceId, ±2h):
New EXE/DLL/PS1/VBS/JS in user/profile/temp/ProgramData paths.
Files created or modified just before/after CMSTP runs.

Check for:
New run keys, services, scheduled tasks, or connection manager profiles that look rogue.
Network & Scope
Pivot to DeviceNetworkEvents around the same time:
Outbound connections related to INF/URL targets.
Multiple hosts hitting the same INF host or URL.
Run the CMSTP query tenant-wide filtered on the same INF path, URL, or directory to find spread.
Outcome: Decide whether this is confirmed malicious (raise/merge into incident) or red-team approved testing.

4.2 Medium – Suspicious but Possibly Legitimate

Typical patterns:
Local INF in non-standard folder but no scriptlet tokens.
Silent/no-UI switches with slightly unusual parent process.
Single host / one-off execution without obvious remote or temp INF paths.

Actions:

Context Validation
Review ParentImage and ParentCmd:
Is this a known VPN client installer or IT deployment script?
Is the user an admin, helpdesk, or engineer performing maintenance?
Check whether the INF file matches a known vendor or internal profile.

Cross-Host & Time Correlation

Use the same query filtered on:
The specific INF path (or directory),
The same parent process,
The same account.
If multiple endpoints show the same uncommon pattern, treat this as High and pivot deeper.
Lightweight Forensics

Spot-check:
Recent file creations in the INF directory.
Child processes of cmstp.exe.
Any follow-on alerts on the same host.

Decision
If you confirm this is part of a legitimate deployment:
Capture exact patterns (parent, INF path, switches, owner team).
Feed into baseline/allow-listing (see Section 5).
If still unclear, escalate for a full L3 review, but keep scope narrow to affected hosts.

4.3 Low – Baseline Candidate / Watch-List

Typical patterns:
CMSTP from expected parents with no INF abuse indicators.
Low RiskScore, e.g. helpdesk user launching a legitimate VPN profile once.

Actions:

Quick Sanity Check#

Confirm:
User/business role (e.g. remote worker installing VPN profile).
Known vendor paths and installers.

Baseline or Monitor
If this pattern recurs and is clearly legitimate:
Document it in your CMSTP baseline.

If it is one-off and odd, keep it in a watch-list and pay attention if it reappears with higher risk signals.
5. Baselining & Suppression (Low Noise in Production)
To keep this rule useful for L2/L3 hunts without drowning in noise:
Baseline Legit CMSTP Usage (14–30 Days)
Run a simplified version of the query without RiskScore filters.

Summarise by:
ParentImage,
INF path directory,

Switch combinations,
Host roles (DeviceName prefixes, OU, etc. where available).
Identify “Good” Patterns

Example baselines:
Corporate VPN installers (known vendor paths under Program Files).

Internal connection-manager deployments managed by IT.
Confirm these patterns with the tool owners.
Create Tight Allow-Patterns
Avoid broad “ignore all cmstp.exe” filters.

Instead, create specific conditions such as:

ParentImage == "vpnclient.exe" AND Cmd has "C:\\Program Files\\Vendor\\Profiles\\"

DeviceName startswith "LAPTOP-" AND Cmd has "C:\\Program Files\\CorpVPN\\"

Implement these either:
Directly in KQL (additional where not(...) expressions), or
In the analytics/custom-detection rule UI as suppression conditions.
Re-Vaidate Baselines Regularly

Re-baseline when:
New VPN/profile tools are rolled out.
OS upgrades or migrations occur.
Admin scripting practices change (e.g. new deployment frameworks).
Recommended Production Setting

For an initial low-noise deployment:
Start with hunt-only mode.

Once comfortable, alert only on:
DetectionTier == "High" or
DetectionTier in ("High","Medium") with no matching allow-patterns.

Revisit thresholds if:
Environments are extremely quiet (you can lower thresholds),
Or noisy (raise RiskScore threshold or tighten conditions further).
