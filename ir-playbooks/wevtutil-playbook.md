# 🛡️ Comprehensive IR Playbooks for Critical LOLBINs

This document contains Incident Response (IR) Playbooks for critical Living Off the Land Binaries (LOLBINs), focusing on in-depth analysis, strategic remediation, and actionable KQL hunt queries (Microsoft Defender/Sentinel).

---

## 1. 📚 IR Playbook: `powershell.exe` (CRITICAL EXECUTION LOLBIN)

PowerShell is the most common and powerful LOLBIN, abused for **code execution**, **in-memory attacks**, and **persistence**.

### 1.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line** (look for `-EncodedCommand`, `-NonInteractive`), **PowerShell Transcript Logs** (if enabled), Parent/Children processes.
* **Escalation**: If unconfirmed or suspicious, flag with `LOLBIN-POWERSHELL` and assign to L3.

### 1.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: Determine if the execution was **fileless**.
2.  **Evidence Collection**: Capture and decode the Base64 string from `-EncodedCommand`. Capture **memory / disk images**. Analyze WMI/Registry for PowerShell-based **persistence**.
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: Highly Obfuscated PowerShell Execution
    DeviceProcessEvents
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    // Look for suspicious flags: Encoded, Hidden, NonInteractive, and download attempts
    | where ProcessCommandLine has_any ("-enc", "-e", "-noni", "-w hidden", "IEX", "Invoke-WebRequest", "Net.WebClient")
    // Filter out common benign noise and focus on suspicious initiators
    | where InitiatingProcessFileName !in ("known_management_agents", "known_patching_services")
    | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
    ```

### 1.3. 🚧 Containment (Advanced)
* Isolate affected endpoints.
* Reset or revoke credentials linked to compromised accounts (prioritize Admin accounts).
* **Immediate Removal of Persistence**: Delete confirmed WMI or Registry persistence entries **before** system reboot.

### 1.4. 📈 Remediation & Hardening (Strategic Actions)
* **Configuration Hardening**:
    * **Enable and Enforce PowerShell Logging**: Script Block, Module, and Transcription Logging.
    * **Constrained Language Mode**: Enforce for standard users to block reflective programming.
    * **AppLocker/WDAC**: Block script execution from user-writeable locations (`Temp`, `Downloads`).

---

## 2. 📚 IR Playbook: `rundll32.exe` (CRITICAL PROXY EXECUTION LOLBIN)

Abused for **proxy execution of malicious DLLs**, **credential theft (LSASS dumping)**, and **persistence**.

### 2.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line** (DLL path, name, and **Entry Point Function**). DLL path (look for suspicious paths like `%TEMP%`).
* **Escalation**: If highly unusual (e.g., `MiniDump` or custom DLL path), flag with `LOLBIN-RUNDLL32` and assign to L3.

### 2.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: Determine if this is **Credential Theft** (`comsvcs.dll,MiniDump`) or **Evasion/Persistence** (`DllRegisterServer`).
2.  **Evidence Collection**: Capture the malicious DLL. **Memory Forensics** (critical if LSASS dumping suspected). Analyze Registry for `rundll32`-based persistence.
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: LSASS Credential Dumping or Suspicious Dll Execution
    DeviceProcessEvents
    | where FileName =~ "rundll32.exe"
    // Look for LSASS dumping attempt
    | where ProcessCommandLine has "comsvcs.dll,MiniDump"
    // OR look for highly suspicious export/flag or DLL loaded from user-writeable path
    or (ProcessCommandLine has_any ("DllRegisterServer", "javascript", "-sta") 
        and ProcessCommandLine matches regex @"[a-z]:\\Users\\|\\AppData\\|\\Temp\\") 
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, AccountName, ReportId
    ```

### 2.3. 🚧 Containment (Advanced)
* Isolate affected endpoints.
* **Prioritized Credential Reset**: If **LSASS dumping** was confirmed, **immediately revoke or reset** all privileged credentials on the host.
* Remove persistence keys; quarantine the malicious DLL file.

### 2.4. 📈 Remediation & Hardening (Strategic Actions)
* **Configuration Hardening**:
    * **Attack Surface Reduction (ASR) Rules**: Block credential theft from the LSASS process.
    * **AppLocker/WDAC**: Block DLL execution from known non-standard, user-writeable paths (`%TEMP%`, `C:\Users\`).
* Create a **baseline of legitimate `rundll32.exe` command lines** to reduce false positives.

---

## 3. 📚 IR Playbook: `vssadmin.exe` (RANSOMWARE PRECURSOR LOLBIN)

Abused to **delete Volume Shadow Copies (VSS)**, inhibiting system recovery (T1490). **Any deletion attempt is highly critical.**

### 3.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line**. **Critical malicious commands**: `delete shadows /all /quiet` or `resize shadowstorage`.
* **Escalation**: If deletion/resize commands are present and unwhitelisted, flag with **`RANSOMWARE-VSSADMIN`** and assign to L3.

### 3.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: The system is compromised. Look for correlated activity *immediately prior* to the delete command (e.g., initial access, credential theft).
2.  **Evidence Collection**: Check Windows Event Logs for VSS-related events. Capture the parent process and any files dropped.
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: Deletion or Manipulation of Volume Shadow Copies (T1490)
    DeviceProcessEvents
    | where FileName has_any ("vssadmin.exe", "wmic.exe", "diskshadow.exe")
    | where ProcessCommandLine has_any (
        "delete shadows",                   // Primary deletion command
        "resize shadowstorage",             // Alternative deletion method
        "shadowcopy delete"                 // WMIC delete command
    )
    | where InitiatingProcessFileName !in ("known_backup_agents", "known_system_management_tools") 
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

### 3.3. 🚧 Containment (Advanced)
* Isolate affected endpoints.
* Reset or revoke credentials.
* **CRITICAL BACKUP CHECK**: Immediately verify the integrity and isolation of *external* or *immutable* backup systems.

### 3.4. 📈 Remediation & Hardening (Strategic Actions)
* **Configuration Hardening**:
    * **AppLocker/WDAC**: Implement a rule to **block the execution of `vssadmin.exe`** for all standard users and restrict its execution to only whitelisted, privileged processes.
    * Ensure EDR/AV is configured to explicitly block commands containing `delete shadows`.
* **Policy Review**: Validate adherence to the **3-2-1 backup rule** (3 copies, 2 media, 1 offsite/immutable).

---

## 4. 📚 IR Playbook: `wevtutil.exe` (DEFENSE EVASION LOLBIN)

Used to **clear event logs** (Defense Evasion, T1070.001). **Treat log clearing as a critical post-exploitation indicator.**

### 4.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line**. **Critical malicious commands**: `wevtutil cl System`, `wevtutil cl Security`, etc.
* **CRITICAL**: Attempt to retrieve the affected log(s) *before* they were cleared from an external logging source (SIEM/Log Aggregator).
* **Escalation**: If `cl` (Clear-Log) is present for a critical log, flag with **`DEFENSE-EVASION-WEVTUTIL`** and assign to L3.

### 4.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: The system is compromised. Look for events *immediately preceding* the `wevtutil` command (the actual exploitation steps).
2.  **Evidence Collection**: Confirm if logs were successfully ingested by the SIEM. Search for forensic artifacts in logs *not* cleared (e.g., PowerShell Operational Log).
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: Attempts to clear critical Windows Event Logs (Defense Evasion)
    DeviceProcessEvents
    | where FileName =~ "wevtutil.exe"
    | where ProcessCommandLine has "cl" or ProcessCommandLine has "clear-log"
    | where ProcessCommandLine has_any ("Security", "System", "Application") // Targeting critical logs
    | where InitiatingProcessFileName !in ("known_management_tools") 
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

### 4.3. 🚧 Containment (Advanced)
* Isolate affected endpoints.
* Reset or revoke credentials.
* **CRITICAL DATA PRESERVATION**: Immediately initiate memory and full disk forensic images to capture the system state.

### 4.4. 📈 Remediation & Hardening (Strategic Actions)
* **Mandatory External Logging**: Ensure all critical logs are **forwarded instantaneously** to an external, immutable SIEM/Log Aggregator.
* **Constrain Execution**:
    * **AppLocker/WDAC**: Implement a rule to **block the execution of `wevtutil.exe`** for all standard users.
* **Detection Improvement**: Set up SIEM alerts for a **sudden, dramatic drop in event log volume** from any single host.

---

## 5. 📚 IR Playbook: `schtasks.exe` (PERSISTENCE & EXECUTION LOLBIN)

Abused for **Persistence** and **Privilege Escalation** by scheduling malicious code execution (T1053.005).

### 5.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line**. **Key flags**: `/create` (new persistence), `/tn` (Task Name), `/tr` (Task Run command/payload), `/ru` (Run As User - check for SYSTEM).
* **Escalation**: If `/create` executes a file from a **user-writeable directory** or launches another **LOLBIN** suspiciously, flag with `LOLBIN-SCHTASKS` and assign to L3.

### 5.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: Identify the persistence mechanism and the scheduled payload. Check for **Privilege Escalation** (`/ru SYSTEM`).
2.  **Evidence Collection**: Retrieve the task XML definition file from `C:\Windows\System32\Tasks\[TaskName]`. Check the **TaskScheduler Operational Log** (Event ID 106, 140) for creation events.
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: schtasks.exe creating a task that executes suspicious commands or files
    DeviceProcessEvents
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create"
    // Look for suspicious task run arguments (/tr)
    | where ProcessCommandLine has_any (
        "/tr \"powershell.exe -enc",             // Encoded PowerShell
        "/tr \"powershell.exe -w hidden",       // Hidden PowerShell
        "/tr \"rundll32.exe",                   // Launching other LOLBINs
        "\\AppData\\", "\\Temp\\", "\\Users\\Public\\" // Files from suspicious directories
    )
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

### 5.3. 🚧 Containment (Advanced)
* Isolate affected endpoints.
* **IMMEDIATE TASK DELETION**: Use the `schtasks /delete /tn "MaliciousTaskName" /f` command.
* Reset credentials.

### 5.4. 📈 Remediation & Hardening (Strategic Actions)
* **Principle of Least Privilege (PoLP)**: Restrict the use of the `schtasks.exe /create` utility to only privileged users.
* **Constrain Execution**:
    * **AppLocker/WDAC**: Block execution of files from user-writeable directories, even when launched by the scheduled task service (`svchost.exe`).
* **Enhanced Monitoring**: Ensure **Task Scheduler Operational Logging** is robustly collected by your SIEM/EDR.

---

## 6. 📚 IR Playbook: `mshta.exe` (LOLBIN)

Used to execute **JScript/VBScript code** contained within HTA files or remotely, often bypassing application whitelisting.

### 6.1. 🔍 L2 Initial Triage & Workflow
* **Data Collection**: Full **command line** (local `.hta` file or remote script URL). Parent and children processes (look for spawns of PowerShell/cmd.exe).
* **Escalation**: Flag with `LOLBIN-MSHTA` and assign to L3.

### 6.2. 🛡️ L3 Threat Investigation & Analysis
1.  **Key Focus**: Common chain is **Email Access** -> **`mshta` Execution** -> **LOLBIN/Payload Spawn**.
2.  **Evidence Collection**: Capture the **`.hta` file** itself for script analysis.
3.  **Cross-Environment Hunt (KQL)**:
    ```kql
    // KQL Hunt: mshta.exe spawning a child process from a user-writeable directory
    DeviceProcessEvents
    | where FileName =~ "mshta.exe"
    | where ProcessCommandLine matches regex @"(?i)\.hta|http(s)?" // Must execute an HTA or remote script
    | join kind=inner (
        DeviceProcessEvents 
        | where InitiatingProcessFileName =~ "mshta.exe"
        | where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe") // Malicious children
        | where FolderPath has_any ("\\Users\\", "\\AppData\\", "\\Temp\\") // Susp
