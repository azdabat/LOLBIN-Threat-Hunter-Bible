# forfiles.exe LOLBIN Detection (L2/L3 – Production)

## 1. Threat Overview

forfiles.exe is a legitimate Windows binary. In modern intrusion tradecraft it is abused to move
execution into a signed, trusted process. This evades naïve allow‑lists and simplistic EDR rules.

Abuse patterns for forfiles.exe in the last few years include:

- Use as a downloader or loader as part of phishing and web‑delivered chains.
- Execution with rare or clearly user‑facing parent processes (Office, browser, mail clients).
- Obfuscated or encoded command lines designed to hide payloads and infrastructure.
- Use in mid‑chain stages (post‑initial access, pre‑lateral movement) rather than at the edges.

Effective detection focuses on **context and behaviour**, not on treating forfiles.exe as inherently malicious.

## 2. MITRE ATT&CK Techniques

- T1005 Data from Local System

## 3. Advanced Hunting Query (MDE)

The following query is written for Microsoft Defender for Endpoint Advanced Hunting
and is designed to be used either interactively or as the basis for a scheduled rule.

```kql
let lookback = 7d;
let HighRiskAccounts = dynamic(["Administrator","Domain Admins","Enterprise Admins"]);
let AllowedParents = dynamic(["explorer.exe","svchost.exe","services.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "forfiles.exe"
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

## 4. Hunter Directives & L3 Pivot Strategy

### 4.1. Process Chain

Rebuild the process tree:
`parent` → **`forfiles.exe`** → `child command`

**Flags to look for:**
* **Parents:** Office applications, browsers, mail clients, script hosts.
* **Children:** `PowerShell`, `cmd`, `rundll32`, `mshta`, `wscript`, `cscript`, `curl`, `certutil` (all are common initial execution targets).
* `/c` invoking scripts or binaries from user directories (e.g., `%TEMP%`, `%APPDATA%`).

### 4.2. File Activity

Pivot to `DeviceFileEvents` **±1h** around the hit:

* **Staging Indicators:** Look for new EXE/DLL/PS1/VBS/JS created or modified **before** the `forfiles` command runs, typically in `%TEMP%`, `%AppData%`, `%ProgramData%`, or `Downloads`.
* **Behavior:** Identify if the EXE/DLL was written → executed → removed shortly after.

### 4.3. Network Behaviour

Check `DeviceNetworkEvents` around the hit:

* **Traffic:** Outbound traffic right after `forfiles` triggers a payload.
* **Infrastructure:** Bare IP connections, newly-observed domains, odd ports.
* **Correlation:** Look for URLs seen directly in `/c` commands (e.g., used by `curl`, PowerShell download cradles, or `mshta`).

### 4.4. Identity & Scope

* **User Role:** Note if `Privileged == Yes` for immediate escalation.
* **Scope Check:**
    * Look for multiple suspicious `forfiles` executions from the same user.
    * Check for recent risky sign-ins or MFA spam associated with the user.
    * See if the `forfiles` pattern is repeating across multiple hosts (campaign-level activity).

---

## 5. Baselining & Suppression

* **Baseline:** Record normal `forfiles` usage over 2–4 weeks.
* **Typical Legitimate Use Cases:**
    * IT/scripts cleaning temp folders.
    * Log rotation jobs.
    * Vendor tools using `forfiles` for maintenance.
* **Tuning:** Allow only **specific known-good command lines**.
* **Maintenance:** Re-baseline after significant software rollouts.

### Severity Guidance:

* **High:** Encoded commands, script proxies, remote URLs.
* **Medium:** `/c` running unsigned EXEs from user paths.
* **Low:** Benign cleanup jobs with expected parents.

## 6. Operational Notes

This is a clean, native rule—no Threat Intelligence (TI) feeds required.

The rule's intent is to cover real-world abuse where `forfiles` is used as a **stealth launcher** or **file-iteration execution proxy**, without flagging standard cleanup or maintenance routines.
