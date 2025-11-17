# 📚 IR Playbook: `rundll32.exe` (CRITICAL LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `rundll32.exe`. As a core Windows process, it is abused to **proxy execution of malicious DLLs**, perform **credential theft (LSASS dumping)**, and achieve **persistence**, often bypassing application control solutions.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `rundll32.exe` is expected (e.g., Control Panel item launches, scheduled maintenance).
* **Baseline Knowledge**: Legitimate `rundll32.exe` should typically execute from `C:\Windows\System32` or `C:\Windows\SysWOW64` and reference a standard Windows DLL.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* **Full command line** executed for `rundll32.exe`. Format is `<DLL Name>,<Entry Point> [Arguments]`.
* **DLL Path and Name**: Is the DLL being loaded from a suspicious path like `%TEMP%`, `%APPDATA%`, or a network share?
* **Entry Point Function**: Note the specific function being called (e.g., `DllRegisterServer`, `MiniDump`, or an ordinal number like `#1`).
* **Parent and first-level children** processes.
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If the command line is **highly unusual** (e.g., custom DLL path, use of `DllRegisterServer`, or JavaScript execution) and is **unconfirmed**, immediately:
    * Flag the case with a **`LOLBIN-RUNDLL32`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Common Attack Vectors)
Determine the intent by examining the command line for known malicious patterns:
* **Credential Theft**: Executing `rundll32.exe comsvcs.dll,MiniDump [PID] [Output Path] full` to dump the **LSASS** process memory. **(CRITICAL EVENT)**
* **Evasion/Persistence**: Calling unusual or non-standard export functions like `DllRegisterServer` or using the **JavaScript** execution method.
* **Masquerading/DLL Side-Loading**: Loading a malicious DLL from a non-standard path.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Capture the Malicious DLL**: Recover the DLL file specified in the command line for reverse engineering and hash analysis.
* **Memory Forensics**: Capture a memory image. If LSASS dumping is suspected, the dumped credentials may be in memory or in the specified output file path.
* **Persistence Analysis**: Check the Registry (`HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run`) for entries referencing the suspicious `rundll32` command.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of the DLL hash, function name, or file path**.
* Search for LSASS dumping attempts across all endpoints.
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

---

## 3. 🚧 Containment (Advanced)

Immediate and aggressive actions to stop the threat actor and prevent further damage.

* **Isolate affected endpoints**.
* **Prioritized Credential Reset**: If **LSASS dumping** was confirmed, treat the user account's credentials (and any privileged credentials on the host) as **compromised** and **immediately revoke or reset them**.
* **Block Indicators**: Block identified malicious **domains, IPs, file hashes, and DLL filenames**.
* **Remove Persistence**: If a registry entry was created using `rundll32.exe`, ensure the registry key is **immediately removed**.
* **DLL Quarantine**: Quarantine the malicious DLL file.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Attack Surface Reduction (ASR) Rules**: Utilize endpoint ASR rules to block **credential theft from the LSASS process** (blocks `MiniDump` calls).
* **Constrain Execution**:
    * **AppLocker/WDAC**: Implement policies to **block DLL execution** from known non-standard, user-writeable paths (`%TEMP%`, `C:\Users\`).
* **Advanced Monitoring**: Ensure **Process Access** logging (e.g., Sysmon Event ID 10) is enabled to monitor processes accessing critical memory (like `lsass.exe`).

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content, focusing on catching the **MiniDump** and **DllRegisterServer** calls.
* **Baseline and Whitelist**: Create a baseline of **known, legitimate `rundll32.exe` command lines** to focus analysis on true anomalies.

### 4.3 Policy Review
* Review whether upstream controls (email, web, identity) could be tuned to catch the intrusion earlier.
