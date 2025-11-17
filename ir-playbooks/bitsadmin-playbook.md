# 📚 IR Playbook: `bitsadmin.exe` (C2 and Exfiltration LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the malicious use of `bitsadmin.exe`. Adversaries use it to **download secondary payloads** (Execution) or **upload stolen data** (Exfiltration) asynchronously, leveraging a native, persistent Windows service (BITS, T1197).

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering (Critical Indicators)
* **Baseline Knowledge**: Legitimate use is common (Windows Update, SCCM). Malicious use is characterized by commands that **combine file creation with a network transfer** or use the `/setnotifyflags 4` flag for stealth.
* Confirm with IT / platform owners whether any **legitimate usage** of `bitsadmin.exe` is expected.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `bitsadmin.exe`. Look specifically for `/transfer`, `/create`, `/addfile`, and `/complete`.
* **Download/Upload URL/Path**: Note the source URL for downloads or the destination path for uploads.
* **Local File Path**: Note where the file was saved or retrieved from (e.g., in a suspicious path like `%TEMP%` or `%APPDATA%`).
* **Parent and first-level children** processes.
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If the command line includes a **download from a non-standard domain/IP** or an **upload of a suspicious file**, and is **unconfirmed**, immediately:
    * Flag the case with a **`LOLBIN-BITSADMIN`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Execution (Download)** or **Exfiltration (Upload)**.
* **Download Focus (Execution)**: The goal is to drop a payload (EXE, DLL, or script).
* **Upload Focus (Exfiltration)**: The command uploads sensitive files (e.g., documents, registry hives) from the local machine to a C2 server.
* **Persistence Focus**: BITS jobs persist across reboots by design.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and **network records**.
* **BITS Job Store**: Analyze the BITS job queue (database file: `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat`) to find persistent or recently completed jobs.
* **Capture Payloads**: Retrieve the downloaded file (if the job completed successfully) for hash analysis.
* **Event Logs**: Check the **BITS Operational Event Log** (ID 3, 5, 6, 8, 10) for detailed job creation and status.
* Capture **memory / disk images** as per local SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment, looking for suspicious flags and transfer patterns.
* Hunt for **reuse of command fragments and infrastructure**.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: Suspicious File Transfer or Persistence via bitsadmin.exe (T1197)
    DeviceProcessEvents
    | where FileName =~ "bitsadmin.exe"
    | where ProcessCommandLine has_any (
        // File Transfer Indicators
        " /transfer ", "/addfile", "/complete",
        // Persistence/Stealth Indicators
        "/create", "/setnotifyflags 4"
    )
    // Filter for common malicious download/upload patterns
    | where ProcessCommandLine matches regex @"http(s)?://" 
        or ProcessCommandLine matches regex @"\b/upload\b"
    // Focus on non-SYSTEM accounts and suspicious paths for downloads
    | where AccountName !endswith "$"
        and ProcessCommandLine has_any ("\\Users\\", "\\AppData\\", "\\Temp\\")
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

---

## 3. 🚧 Containment (Advanced)

Immediate actions to stop the BITS transfer, prevent execution, and block further damage.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **IMMEDIATE BITS JOB CANCELLATION**: If the job is active, use the command `bitsadmin /cancel {JobID}` to stop any ongoing transfers and remove the job from the queue.
* **Block Indicators**: Block identified malicious domains, IPs, and file hashes.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Constraint and Application Control (L3 Action)
* **AppLocker/WDAC Policy**: Implement strict application control policies to **block `bitsadmin.exe` execution** for all standard users.
    * **Exception Handling**: Create very narrow **Publisher or Hash-based Allow Rules** only for specific, whitelisted administrative accounts or management agents.
    * **URL/IP Filtering**: Configure proxy/web gateway controls to block BITS traffic (user-agent: "Microsoft BITS") to known malicious or suspicious TLDs/IP ranges.

### 4.2 Logging and Visibility Enhancement (L3 Action)
* **BITS Operational Log**: Ensure the **BITS Operational Event Log** is configured for maximum verbosity and reliably forwarded to the SIEM/Log Aggregator.
* **PowerShell/Script Logging**: Ensure **PowerShell Script Block Logging** and **WSH/VBScript logging** are fully enabled to capture the initial command that launched `bitsadmin`.
* **Regression Testing**: Validate that existing EDR/SIEM rules effectively detect the full kill chain.

### 4.3 Policy Review
* Review whether **upstream controls** (e.g., email security, web gateway) could have blocked the initial access that led to the execution of the BITS command.
