# 📚 IR Playbook: `certutil.exe` (LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `certutil.exe`, a Windows utility commonly abused as a Living Off the Land Binary (LOLBIN), often for downloading or decoding files (e.g., base64).

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `certutil.exe` is expected on the affected host or by the user (e.g., certificate enrollment).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `certutil.exe` (e.g., containing `urlcache`, `decode`, or `verifyctl`).
* **Parent and first-level children** processes of the `certutil` execution.
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed**, close the alert as benign administrative noise.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-CERTUTIL`** tag.
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
* Export relevant process, file, and network records (e.g., web requests initiated by `certutil`).
* Capture **payloads** where possible for reverse engineering (e.g., files downloaded or decoded).
* Capture **memory / disk images** as per local SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of command fragments and infrastructure** (e.g., specific URLs or file names).
* Hunt for similar activity across other **hosts, users, and business units**.
    ```bash
    # Example Hunt Query (Pseudo-Code)
    WHERE process_name = "certutil.exe" 
      AND command_line LIKE "%urlcache% -split -f%"
      AND NOT user IN ("known_pkiservice_accounts")
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
* Where feasible, **constrain or limit the usage of `certutil.exe`** to specific, legitimate contexts via:
    * AppLocker or Windows Defender Application Control (WDAC).
    * Third-party application control solutions.

### 4.2 Documentation & Testing
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly).

### 4.3 Control Tuning
* Review whether **upstream controls** (e.g., email security, web gateway, identity protection) could be tuned to catch the initial stages of this intrusion earlier (e.g., preventing the initial phishing email or payload delivery).
