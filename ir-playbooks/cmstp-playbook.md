# 📚 IR Playbook: `cmstp.exe` (LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `cmstp.exe` (Connection Manager Profile Installer), a Windows utility commonly abused as a Living Off the Land Binary (LOLBIN) for **execution** and **UAC bypass**.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `cmstp.exe` is expected on the affected host or by the user (e.g., VPN/network connection profile installation).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `cmstp.exe` (malicious use typically includes the `/au` flag for unattended install).
* **Parent and first-level children** processes of the `cmstp` execution, paying close attention to any **unusual child processes** spawned (e.g., PowerShell, cmd.exe).
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed**, close the alert as benign administrative noise.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-CMSTP`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment
Determine if this is: **opportunistic malware**, a **targeted intrusion**, or **benign admin noise**.
* **Look for signs of a wider intrusion (ATT&CK):**
    * Multiple tactics present (Execution, Persistence, Lateral Movement, C2).
    * Signs of **hands-on-keyboard** activity.

### 2.2 Evidence Collection
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Capture the malicious INF or CAB file** that was executed by `cmstp.exe`.
* Capture **payloads** where possible for reverse engineering (e.g., final executables dropped by the INF).
* Capture **memory / disk images** as per local SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of the command fragment (`/au`), file hash, or filename** of the malicious INF/CAB.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: cmstp.exe spawning unusual children, often with the UAC bypass flag
    DeviceProcessEvents
    | where FileName == "cmstp.exe"
    | where ProcessCommandLine contains "/au" // Unattended install flag
    | where InitiatingProcessFileName !in ("explorer.exe", "msiexec.exe") // Filter out common initiators
    | where SHA256 !in ("known_good_hash_list") // Filter out known legitimate files
    | join kind=leftouter (
        DeviceProcessEvents 
        | where InitiatingProcessFileName == "cmstp.exe"
        | where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe") // Malicious children
    ) on InitiatingProcessId
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, AccountName
    ```

---

## 3. 🚧 Containment

Immediate actions to stop the threat actor and prevent further damage.

* **Isolate affected endpoints** where malicious activity is confirmed or strongly suspected.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **Block identified malicious indicators** (domains, IPs, file hashes) at relevant network and endpoint controls.

---

## 4. 📈 Remediation & Hardening

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Constraint
* Where feasible, **constrain or limit the usage of `cmstp.exe`** to specific, legitimate contexts via:
    * AppLocker or Windows Defender Application Control (WDAC).
    * Third-party application control solutions.
    * *Focus: Block the use of the `/au` flag for non-standard paths.*

### 4.2 Documentation & Testing
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly).

### 4.3 Control Tuning
* Review whether **upstream controls** (e.g., email security, web gateway, identity protection) could be tuned to catch the initial stages of this intrusion earlier (e.g., preventing the delivery of the malicious INF/CAB file).
