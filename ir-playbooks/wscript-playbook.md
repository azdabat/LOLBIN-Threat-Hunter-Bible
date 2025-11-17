# 📚 IR Playbook: `wscript.exe` (Script Execution LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `wscript.exe` (Windows Script Host). Adversaries use it for **Execution** and **Initial Access** via malicious VBScript (`.vbs`) or JScript (`.js`) files, often delivered via phishing to download and launch secondary payloads.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `wscript.exe` is expected (legacy batch jobs, admin scripts).
* **Baseline Knowledge**: Malicious scripts are often executed from user-writeable directories (e.g., `Downloads`, `%TEMP%`) and may use the stealth flag `//B`.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `wscript.exe`. **Critical flags to note**: `//B` (suppress UI), `//E:jscript` or `//E:vbscript`.
* **Script File Path and Name**: Is the script file (`.vbs` or `.js`) located in a suspicious path?
* **Parent and first-level children** processes. Look for suspicious parents (MS Office/email clients) and suspicious children (like `powershell.exe`, `cmd.exe`).
* Any other related security **alerts** on same host/user in the last 7 days.

### 1.3 Escalation
* If the script is executed from a **user-writeable directory** or spawns another **LOLBIN** (`powershell.exe`, `bitsadmin.exe`, etc.), immediately:
    * Flag the case with a **`LOLBIN-WSCRIPT`** tag.
    * **Assign to L3** for high-priority investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Execution** of a dropper, **Initial Access**, or **Persistence**.
* **Key Focus**: The script's primary function is usually to download a second stage payload or to establish persistence (via Registry Run keys or `schtasks.exe`).
* **Correlated Activity**: Look for network connections originating from `wscript.exe` or its subsequent child process immediately after execution.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Capture the Script File**: Retrieve the `.vbs` or `.js` file for static analysis. Look for obfuscation and calls to network objects (e.g., `ActiveXObject`).
* **Check Persistence**: Analyze Registry (Run keys) and Task Scheduler for new entries created by the script.
* **Capture Payloads**: Retrieve any secondary executables or scripts dropped or downloaded.
* Capture **memory / disk images** as per SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **hash reuse** of the malicious script or subsequent payloads.
* Hunt for **common child processes** spawned by `wscript.exe` across the environment.
    ```kql
    // KQL Hunt: wscript.exe executing scripts from suspicious directories and spawning LOLBINs
    DeviceProcessEvents
    | where FileName =~ "wscript.exe"
    | where ProcessCommandLine matches regex @"(?i)\.vbs|\.js"
    // Look for execution from user-writeable paths, typical of phishing/downloads
    | where ProcessCommandLine has_any ("\\Users\\", "\\AppData\\", "\\Temp\\", "\\Downloads\\")
    | join kind=leftouter (
        DeviceProcessEvents 
        | where InitiatingProcessFileName =~ "wscript.exe"
        // Look for typical payloads launched by the script
        | where FileName has_any ("powershell.exe", "cmd.exe", "mshta.exe", "bitsadmin.exe", "certutil.exe", "explorer.exe") 
    ) on InitiatingProcessId
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ChildProcessCommandLine, ScriptPath=ProcessCommandLine, AccountName
    ```

---

## 3. 🚧 Containment (Advanced)

Immediate actions to stop the threat and prevent further damage.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the account(s) involved.
* **Delete Malicious Files**: Quarantine and delete the malicious script file (`.vbs`/`.js`) and any secondary payloads.
* **Block Indicators**: Block identified malicious domains, IPs, and file hashes.
* **Remove Persistence**: If registry or scheduled task persistence was created, immediately remove those entries.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Script Blocking**:
    * **AppLocker/WDAC**: Implement policies to **block execution of VBScript (`.vbs`) and JScript (`.js`) files** entirely for standard users, or restrict execution only to signed scripts from whitelisted system paths.
* **File Type Blocking**: Configure email/web gateways to block delivery of `.js`, `.vbs`, and `.wsf` files.
* **Registry Hardening**: Restrict WSH/VBS/JS execution via Registry policy for low-privilege users.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content, focusing on detecting the *child process* spawn (e.g., `wscript.exe` -> `powershell.exe`).
* **Monitor COM Objects**: Monitor for suspicious instantiation of COM/ActiveX objects commonly used for networking originating from `wscript.exe`.

### 4.3 Policy Review
* Review **Email Security**: Ensure robust filtering and user awareness training are in place, as this LOLBIN is heavily reliant on user interaction (phishing/malicious documents) for initial execution.
