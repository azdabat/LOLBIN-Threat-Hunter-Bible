# 📚 IR Playbook: `mshta.exe` (LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `mshta.exe`. Malicious use typically involves executing remote or local scripts (JScript/VBScript) embedded in HTML applications (`.hta` files) for **initial execution** and **persistence**.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `mshta.exe` is expected on the affected host or by the user (legitimate use is rare in enterprise environments, primarily for old legacy applications).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `mshta.exe`. Note if it's executing a **local `.hta` file** or a **remote script URL**.
* **Parent and first-level children** processes of the `mshta` execution. Look specifically for spawns of **PowerShell, cmd.exe, or other LOLBINs** (e.g., `certutil`, `bitsadmin`).
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed** (e.g., legacy app launch), close the alert as benign.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-MSHTA`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is: **opportunistic malware**, a **targeted intrusion**, or **benign admin noise**.
* **Common Attack Chains**: Malicious `mshta` execution often follows a chain:
    1. **Initial Access**: Email attachment (HTA file) or malicious link.
    2. **Execution**: `mshta.exe` runs the HTA file.
    3. **Action**: The HTA's embedded script (VBS/JS) executes a follow-on payload using another LOLBIN.
* **Look for signs of a wider intrusion (ATT&CK):**
    * Multiple tactics present (Execution, Persistence, Lateral Movement, C2).
    * Signs of **hands-on-keyboard** activity.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and **network records** associated with `mshta.exe` and its children.
* **Capture the `.hta` file itself**: This file contains the malicious script (often obfuscated) that drives the rest of the attack.
* **Capture payloads** where possible (e.g., final DLLs or EXEs downloaded or dropped).
* Capture **memory / disk images** as per local SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of script code fragments, download URLs, or unique variable names**.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: mshta.exe spawning a child process from a user-writeable directory
    DeviceProcessEvents
    | where FileName =~ "mshta.exe"
    | where ProcessCommandLine matches regex @"(?i)\.hta|http(s)?" // Must execute an HTA or remote script
    | where InitiatingProcessFileName !in ("known_benign_apps") 
    | join kind=inner (
        DeviceProcessEvents 
        | where InitiatingProcessFileName =~ "mshta.exe"
        | where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe") // Malicious children
        | where FolderPath has_any ("\\Users\\", "\\AppData\\", "\\Temp\\") // Suspicious write location
    ) on InitiatingProcessId
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, AccountName, FolderPath
    ```

---

## 3. 🚧 Containment

Immediate actions to stop the threat actor and prevent further damage.

* **Isolate affected endpoints** where malicious activity is confirmed or strongly suspected.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **Block identified malicious indicators** (domains, IPs, file hashes) at relevant network and endpoint controls. **Focus on blocking the C2 domain/IP found in the HTA script.**
* **Delete the HTA file and any dropped payloads** from the host to prevent recurrence or re-execution.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Constrain Execution of HTA/Scripts**: As legitimate use of `mshta.exe` is minimal, consider highly restrictive controls:
    * **AppLocker/WDAC**: Implement a policy to **block `mshta.exe`** execution entirely for most user roles. Alternatively, block execution of HTA files from user-writeable directories (e.g., `Downloads`, `Temp`).
* **Enhanced Script Logging**: Ensure **PowerShell Script Block Logging** and **AMS-enabled security products** are fully configured, as `mshta` often launches malicious PowerShell code.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly).
* **Review Upstream Controls**: Ensure email and web security gateways are actively scanning and blocking **`.hta` file attachments** and common scripting obfuscation techniques.

### 4.3 Policy Review
* **Review File Extensions**: Block the execution of `.hta` files via policy if they are not strictly required for business operations.
