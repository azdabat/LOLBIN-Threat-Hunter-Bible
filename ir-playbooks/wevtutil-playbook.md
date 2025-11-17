# 📚 IR Playbook: `wevtutil.exe` (Defense Evasion LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `wevtutil.exe` (Windows Event Log Utility). Adversaries use this tool to **clear event logs**, destroying forensic evidence of their activities (Defense Evasion, T1070.001). **Any attempt to clear event logs must be treated as a critical post-exploitation indicator.**

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `wevtutil.exe` is expected (rare, usually automated log rotation).
* **Baseline Knowledge**: Clearing logs is almost never a legitimate administrative task. The critical command is `clear-log` or `cl`.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `wevtutil.exe`. **Critical malicious commands to note**:
    * `wevtutil cl System`
    * `wevtutil cl Security`
    * `wevtutil cl Application`
* **Parent and first-level children** processes.
* **CRITICAL**: Attempt to retrieve the last few hours of the affected log(s) *before* they were potentially cleared, if possible from an external logging source (SIEM/Log Aggregator).
* Any other related security **alerts** on same host/user in the last 7 days.

### 1.3 Escalation
* If the command line contains **`cl`** (Clear-Log) for any critical logs (`Security`, `System`, `Application`), immediately:
    * Flag the case with a **`DEFENSE-EVASION-WEVTUTIL`** tag.
    * **Assign to L3** for immediate, high-priority investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Defense Evasion** (T1070.001).
* **Key Focus**: The system is compromised, and the attacker is attempting to cover their tracks. Assume all logs on the local host are unreliable starting from the time of the command execution.
* **Correlated Activity**: Look for events *immediately preceding* the `wevtutil` command, as these represent the attacker's actual exploitation steps.
* **Alternative Log Clearing**: Check for use of PowerShell's `Clear-EventLog` cmdlet or direct file deletion.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Log Aggregator Check**: Confirm if the cleared logs were successfully ingested by the SIEM/Log Aggregator *before* the clear command was executed. This is the primary recovery source.
* **Forensic Artifacts**: Search for specific logs that are *not* cleared by `wevtutil cl`, such as the **PowerShell Operational Log** or **TaskScheduler Operational Log**.
* Capture **memory / disk images** as per SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for the **specific command fragments** (`wevtutil cl`) used across all endpoints.
* Hunt for the use of other log-clearing methods (`Clear-EventLog`).
    ```kql
    // KQL Hunt: Attempts to clear critical Windows Event Logs (Defense Evasion)
    DeviceProcessEvents
    | where FileName =~ "wevtutil.exe"
    | where ProcessCommandLine has "cl" or ProcessCommandLine has "clear-log"
    | where ProcessCommandLine has_any ("Security", "System", "Application") // Targeting critical logs
    | where InitiatingProcessFileName !in ("known_management_tools") // Filter known legitimate log rotation
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

---

## 3. 🚧 Containment (Advanced)

Immediate actions to secure the environment and preserve any remaining evidence.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **CRITICAL DATA PRESERVATION**: Immediately initiate memory and full disk forensic images.
* Block identified malicious domains, IPs, and hashes.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Mandatory External Logging (Log Forwarding)**: Ensure all critical endpoint logs are **forwarded instantaneously** to an external, immutable SIEM or log aggregator.
* **Constrain Execution**:
    * **AppLocker/WDAC**: Implement a rule to **block the execution of `wevtutil.exe`** for all standard users and restrict its use to only whitelisted, privileged processes/scripts.
* **Log Permissions**: If possible without breaking legitimate logging, adjust ACLs on the `.evtx` files to make them Read-Only for all but the `SYSTEM` account.

### 4.2 Detection Improvement
* Add this specific, critical scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the log clear attempt fires the highest severity alert).
* **Monitor Log Volume**: Set up SIEM alerts for a **sudden, dramatic drop in event log volume** from any single host, as this is a passive indicator of log clearing.

### 4.3 Policy Review
* Review whether upstream controls (email, web, identity) could have prevented the initial access that allowed the attacker to reach the defense evasion stage.
