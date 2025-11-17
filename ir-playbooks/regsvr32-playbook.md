# 📚 IR Playbook: `regsvr32.exe` (LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `regsvr32.exe`. Malicious use is commonly associated with **fileless execution** via **`scrobj.dll`** (Squiblydoo technique) to download and execute remote XML/SCT script files.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `regsvr32.exe` is expected on the affected host or by the user (legitimate use is typically limited to software installation/uninstallation/updates).
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `regsvr32.exe`. Pay special attention if the command uses the **`/s`** (silent) flag or references **`scrobj.dll`**.
* The **path of the DLL** being registered/unregistered. Malicious use often targets files in user-writeable or temporary directories.
* **Parent and first-level children** processes of the `regsvr32` execution.
* Any other related security **alerts** on the same host/user in the last 7 days.

### 1.3 Escalation
* If legitimate usage is **confirmed** (e.g., authorized software installer), close the alert as benign.
* If usage is **unconfirmed or suspicious**:
    * Flag the case with a **`LOLBIN-REGSVR32`** tag.
    * **Assign to L3** for deeper investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is: **opportunistic malware**, a **targeted intrusion**, or **benign admin noise**.
* **Common Attack Chains**: Malicious `regsvr32` execution almost always involves:
    1. **Invocation of `scrobj.dll`**: The command looks like `regsvr32 /s /u /i:[Remote URL or Local Path to SCT/XML] scrobj.dll`.
    2. **Execution**: The SCT/XML file is downloaded (often filelessly) and executes embedded VBScript or JScript.
* **Key Focus**: Confirming the use of **`scrobj.dll`** indicates a high likelihood of compromise and fileless activity.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and **network records** associated with `regsvr32.exe`. Look for network connections to download the remote SCT/XML file.
* **Capture the script content**: If a remote URL was used, attempt to retrieve the XML/SCT file to analyze the malicious VBScript/JScript.
* **Capture payloads** where possible (e.g., subsequent DLLs or EXEs dropped by the script).
* Capture **memory / disk images** as per local SOPs for high-severity cases, as the execution is often in-memory.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for **reuse of remote URLs, file paths, or specific script fragments**.
* Hunt for similar activity across other **hosts, users, and business units**.
    ```kql
    // KQL Hunt: regsvr32.exe loading the scripting component to execute remote/suspicious code
    DeviceProcessEvents
    | where FileName =~ "regsvr32.exe"
    | where ProcessCommandLine has "scrobj.dll" // Target of the Squiblydoo technique
    | where ProcessCommandLine has_any ("http", "https") // Indicates remote script download
    | where ProcessCommandLine contains "/i:" // Execution with installation parameters
    | join kind=leftouter (
        DeviceNetworkEvents
        | where InitiatingProcessFileName =~ "regsvr32.exe"
    ) on DeviceId, InitiatingProcessId
    | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, RemoteUrl, AccountName
    ```

---

## 3. 🚧 Containment

Immediate actions to stop the threat actor and prevent further damage.

* **Isolate affected endpoints** where malicious activity is confirmed or strongly suspected.
* **Reset or revoke credentials** linked to the compromised account(s) involved.
* **Block identified malicious indicators** (domains, IPs, file hashes) at relevant network and endpoint controls. **Prioritize blocking the URL/domain used to host the malicious SCT file.**
* **Prevent Re-execution**: If a local malicious DLL or SCT file was used, ensure it is safely deleted and quarantined.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **Constrain Execution**: Due to the high risk of fileless attacks, constrain `regsvr32.exe` usage:
    * **AppLocker/WDAC**: Implement a policy to **block `regsvr32.exe`** execution entirely, or restrict its use to signing authorities or specific paths (e.g., block when executed from `C:\Users\` or `C:\Temp\`).
    * **Block `scrobj.dll`**: Where possible, restrict the ability of `regsvr32.exe` to load `scrobj.dll`.
* **Network Layer Filtering**: Configure outbound firewalls or proxy servers to specifically block executable downloads from known malicious domains or domains requested directly by `regsvr32.exe`.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content (ensure the original alert fires correctly).
* **Review Upstream Controls**: Ensure email and web security gateways are actively scanning and blocking **SCT and XML file attachments** or links that lead directly to these file types.
