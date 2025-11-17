# 📚 IR Playbook: `powershell.exe` (CRITICAL LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `powershell.exe`. Malicious PowerShell is a common vector for **code execution**, **downloading payloads**, **persistence**, and **in-memory attacks** due to its inherent capabilities.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `powershell.exe` is expected (e.g., configuration management, scheduled tasks, monitoring agents).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* **Full command line** executed for `powershell.exe`. Look for signs of obfuscation like `-EncodedCommand`, `-NonInteractive`, or `-WindowStyle Hidden`.
* **Parent and first-level children** processes of the PowerShell execution.
* **PowerShell Transcript Logs**: Export any relevant logs that capture the actual code run inside the PowerShell session (if logging is enabled).
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed** (e.g., standard patch management script), close the alert as benign.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-POWERSHELL`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment
Determine if this is: **opportunistic malware**, a **targeted intrusion**, or **benign admin noise**.
* **Look for signs of a wider intrusion (ATT&CK):**
    * Multiple tactics present (Execution, Persistence, Lateral Movement, C2).
    * Signs of **hands-on-keyboard** activity.
    * **Key Focus**: Determine if the execution was **fileless** (code executed directly in memory).

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Capture and decode the PowerShell script or payload**: If the command line contains `-EncodedCommand`, decode the Base64 string to retrieve the actual code.
* **Capture memory / disk images** as per local SOPs for high-severity cases, as memory is often the only place to recover fileless payloads.
* **Analyze WMI/Registry for persistence**: Check standard locations where PowerShell code is stored for persistence (e.g., WMI Event Subscriptions, Run keys).

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of decoded code fragments, IP addresses, or unique variable names**.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: Highly Obfuscated PowerShell Execution
    DeviceProcessEvents
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    // Look for suspicious flags: Encoded, Hidden, NonInteractive, and download attempts
    | where ProcessCommandLine has_any ("-enc", "-e", "-noni", "-w hidden", "IEX", "Invoke-WebRequest", "Net.WebClient")
    // Filter out very common benign noise (tune this for your environment)
    | where ProcessCommandLine !startswith "powershell.exe -NoProfile -ExecutionPolicy Bypass" 
    | where InitiatingProcessFileName !in ("known_management_agents", "known_patching_services")
    | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
    ```

---

## 3. 🚧 Containment

Immediate actions to stop the threat actor and prevent further damage.

* **Isolate affected endpoints** where malicious activity is confirmed or strongly suspected.
* **Reset or revoke credentials** linked to the compromised account(s) involved. **Prioritize accounts with administrative privileges.**
* **Block identified malicious indicators** (domains, IPs, file hashes) at relevant controls.
* **Immediate Removal of Persistence**: If WMI or Registry persistence was confirmed, delete the malicious entry **before** system reboot.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Enable and Enforce PowerShell Logging**: This is the single most critical step. Configure via Group Policy or MDM:
    * **Script Block Logging**: Captures the actual code executed, even if obfuscated.
    * **Module Logging**: Captures pipeline execution events.
    * **Transcription Logging**: Captures session input/output.
* **Constrain Execution**: Where feasible, constrain usage of `powershell.exe` to specific contexts via:
    * **AppLocker/WDAC**: Block execution of PowerShell scripts from user-writeable locations (`Temp`, `Downloads`, user profiles).
    * **Constrained Language Mode**: For endpoints that do not require full PowerShell capabilities, enforce **Constrained Language Mode** to block reflective programming, access to Windows APIs, and COM objects.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly and transcript logs are ingested).
* **Review Control Tuning**: Review whether upstream controls (e.g., email, web, identity) could be tuned to catch the intrusion earlier (e.g., monitoring access to specific PowerShell modules or functions).

### 4.3 Policy Review
* **Review Execution Policy**: While the Execution Policy is not a security boundary (easily bypassed), ensure it is set to at least `RemoteSigned` for workstations and `AllSigned` for servers. **Do not rely on this alone for security.**
