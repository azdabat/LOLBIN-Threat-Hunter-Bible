# 📚 IR Playbook: `vssadmin.exe` (Ransomware Precursor LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `vssadmin.exe` (Volume Shadow Copy Service Admin). Adversaries use this tool to **delete Volume Shadow Copies (VSS)**, inhibiting system recovery and forcing victims to pay a ransom. **Any attempt to delete VSS is considered highly critical.**

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `vssadmin.exe` is expected (usually only for automated backup solutions).
* **Baseline Knowledge**: Deletion commands should be rare on non-server endpoints.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `vssadmin.exe`. **Critical malicious commands to note**:
    * `vssadmin delete shadows /all /quiet`
    * `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB`
* **Parent and first-level children** processes (look for parents like `cmd.exe`, `powershell.exe`).
* The **privilege level** of the process (deletion requires **Administrator** privileges).
* Any other related security **alerts** on same host/user in the last 7 days.

### 1.3 Escalation
* If the command line contains **`delete shadows`** or **`resize shadowstorage`** and is **not explicitly linked to a known, whitelisted backup application**, immediately:
    * Flag the case with a **`RANSOMWARE-VSSADMIN`** tag.
    * **Assign to L3** for immediate, high-priority investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Inhibit System Recovery (Ransomware Impact)** or highly rare benign noise.
* **Key Focus**: The system is already compromised. Look for correlated activity:
    * Attempts to stop services (e.g., `net stop "sql server"`).
    * Use of other VSS manipulation tools like `wmic.exe` or `diskshadow.exe`.
    * Subsequent activity: Massive file writes/renames characteristic of encryption.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and **network records**.
* **Windows Event Logs**: Check the System logs for VSS-related events confirming the deletion attempt.
* **Capture Payloads**: Focus on the parent process and any files dropped immediately prior to the `vssadmin` command.
* Capture **memory / disk images** as per SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for the **specific command fragments** used across all endpoints.
* Hunt for the use of other VSS manipulation tools like `wmic.exe` or `diskshadow.exe`.
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

---

## 3. 🚧 Containment (Advanced)

Immediate actions to stop the threat actor and protect remaining systems/backups.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **Block indicators** identified during the attack.
* **CRITICAL BACKUP CHECK**: Immediately verify the integrity and isolation (air-gap) of the organization's *external* or *immutable* backup system.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Constrain Execution (Defense-in-Depth)**:
    * **AppLocker/WDAC**: Implement a rule to **block the execution of `vssadmin.exe`** for all standard users, and restrict its execution path to only whitelisted, privileged processes.
* **VSS Protection**:
    * Implement **Volume Shadow Copy Service Protection** measures.
* **Endpoint Protection**: Ensure EDR/AV is configured to explicitly block commands containing `delete shadows` or `resize shadowstorage` from running under common scripting interpreters.

### 4.2 Detection Improvement
* Add this specific, critical scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensuring the VSS delete/resize attempt fires the highest severity alert).
* **Alert Correlation**: Tune security rules to immediately correlate a `vssadmin delete shadows` event with any preceding file enumeration or credential access attempts.

### 4.3 Policy Review
* **Backup Strategy Review**: Validate that the organization adheres to the **3-2-1 backup rule** (3 copies of data, 2 different media types, 1 copy offsite/immutable). The failure of VSS indicates a need for stronger offline/immutable backup protection.
