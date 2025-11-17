# 📚 IR Playbook: `curl.exe` (LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `curl.exe`, a Windows utility commonly abused as a Living Off the Land Binary (LOLBIN) for **downloading files** or interacting with **C2 infrastructure**.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `curl.exe` is expected on the affected host or by the user (e.g., development tools, API scripting).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `curl.exe`, specifically noting the **URL, IP address, and output file** using the `-o` or `-O` flags.
* **Parent and first-level children** processes of the `curl` execution.
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed**, close the alert as benign administrative noise.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-CURL`** tag.
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
* Export relevant process, file, and **network records** (e.g., the full URL and the downloaded file hash).
* **Capture the payload** (file downloaded by curl) where possible for reverse engineering.
* Capture **memory / disk images** as per local SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of the IP address, domain, file hash, or filename** used in the `curl` command.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: curl.exe downloading files and saving them to unusual paths
    DeviceProcessEvents
    | where FileName == "curl.exe"
    | where ProcessCommandLine has_any ("-o", "-O") // Look for download and save operations
    | where ProcessCommandLine matches regex @"(?i)http(s)?:\/\/(.*?)" // Must contain a URL
    | where ProcessCommandLine matches regex @"(?i)(.exe|.dll|.ps1|.vbs|.js)" // Look for suspicious file extensions
    | where InitiatingProcessFileName !in ("known_web_browser_names", "known_patching_services") // Filter out benign noise
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, AccountName
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
* Where feasible, **constrain or limit the usage of `curl.exe`** to specific, legitimate contexts via:
    * AppLocker or Windows Defender Application Control (WDAC), focusing on blocking `curl` when executed from unusual parent processes.
    * Third-party application control solutions.
    * *Focus: Restrict connections to approved IP ranges or domains.*

### 4.2 Documentation & Testing
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly).

### 4.3 Control Tuning
* Review whether **upstream controls** (e.g., web gateway, identity protection) could be tuned to catch the initial stages of this intrusion earlier (e.g., monitoring HTTP/HTTPS requests that bypass standard browsers).
