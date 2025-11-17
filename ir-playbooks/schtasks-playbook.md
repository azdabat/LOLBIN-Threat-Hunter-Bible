# 📚 IR Playbook: `schtasks.exe` (Persistence & Execution LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `schtasks.exe` (Task Scheduler Command Line Utility). Adversaries use this tool primarily to achieve **Persistence** and **Privilege Escalation** by scheduling the execution of malicious code at specified intervals (e.g., on logon, at system startup, or hourly).

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `schtasks.exe` is expected (e.g., automated backups, patch management, system health checks).
* **Baseline Knowledge**: Legitimate tasks usually run under the `SYSTEM` or `Service` accounts and execute standard Windows binaries, often referencing files in `Program Files`.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `schtasks.exe`. **Key flags to note**:
    * **`/create`**: Indicates a new persistence mechanism.
    * **`/tn`**: The Task Name (often random, misleading, or legitimate-sounding like "GoogleUpdate").
    * **`/tr`**: The Task Run command (the malicious payload).
    * **`/sc`**: The Schedule Type (e.g., `ONLOGON`, `MINUTE`, `HOURLY`).
    * **`/ru`**: The Run As User (e.g., `SYSTEM` for privilege escalation).
* **Parent and first-level children** processes (look for the parent that initiated the `schtasks /create` command).
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If the command line creates a task (`/create`) that executes a file from a **user-writeable directory** (`%APPDATA%`, `%TEMP%`) or launches another **LOLBIN** with suspicious flags, immediately:
    * Flag the case with a **`LOLBIN-SCHTASKS`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Execution**, **Persistence**, or **Privilege Escalation (T1053.005)**.
* **Persistence Focus**: Check the task XML definition located in `C:\Windows\System32\Tasks` for the task name specified by `/tn`.
* **Payload Analysis**: Identify the actual command/script (`/tr`) that the task executes. This command is often obfuscated PowerShell or a reference to a malicious file.
* **Privilege Escalation**: If the task runs as `/ru SYSTEM` or another high-privilege account.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Task Configuration File**: Retrieve the XML file from `C:\Windows\System32\Tasks\[TaskName]` to get the full, non-truncated configuration.
* **Windows Event Logs**: Check the **TaskScheduler Operational Log** for Event ID **106** (Task Registered/Created) and **140** (Task Updated) to validate the creation time and user.
* **Capture Payloads**: Retrieve any malicious files referenced in the task's `/tr` argument.
* Capture memory / disk images as per SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of the malicious Task Name (`/tn`) or the payload command (`/tr`) fragments**.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: schtasks.exe creating a task that executes suspicious commands or files
    DeviceProcessEvents
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create"
    // Look for suspicious task run arguments (/tr)
    | where ProcessCommandLine has_any (
        "/tr \"powershell.exe -enc",             // Encoded PowerShell
        "/tr \"powershell.exe -w hidden",       // Hidden PowerShell
        "/tr \"cmd.exe /c start",               // Command launching start
        "/tr \"rundll32.exe",                   // Launching other LOLBINs
        "\\AppData\\", "\\Temp\\", "\\Users\\Public\\" // Files from suspicious directories
    )
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

---

## 3. 🚧 Containment (Advanced)

Immediate actions to stop the persistence mechanism and prevent further payload execution.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the account(s) involved.
* **IMMEDIATE TASK DELETION**: Use the `schtasks /delete /tn "MaliciousTaskName" /f` command or the Task Scheduler GUI to immediately remove the malicious scheduled task.
* Block identified malicious domains, IPs, and hashes.
* Delete the XML configuration file and the malicious payload file referenced in the task.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Principle of Least Privilege (PoLP)**: Restrict the use of the `schtasks.exe /create` utility to only privileged users.
* **Constrain Execution**:
    * **AppLocker/WDAC**: Implement policies to block the execution of files from user-writeable directories (where malicious task payloads are often dropped), even when launched by `svchost.exe` (the process that runs the scheduled task).
* **Enhanced Monitoring**: Ensure **Task Scheduler Operational Logging** (Event ID 106, 140) is robustly collected by your SIEM/EDR.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content, ensuring new task creations are not masked by legitimate administrative noise.
* **Whitelisting/Baselines**: Create a baseline of legitimate scheduled tasks in your environment.

### 4.3 Policy Review
* Review whether upstream controls (email, web, identity) could be tuned to catch the intrusion earlier.
