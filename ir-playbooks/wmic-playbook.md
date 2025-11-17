# 📚 IR Playbook: `wmic.exe` (Recon, Lateral Movement, and Evasion LOLBIN)

This playbook is designed for security teams (L2/L3 analysts) to investigate and respond to alerts related to the potentially malicious use of `wmic.exe` (Windows Management Instrumentation Command-line). It is a highly versatile utility abused for **system reconnaissance**, **lateral movement** (via `psexec` functionality), **defense evasion** (e.g., deleting shadow copies), and **execution** of payloads.

---

## 1. 🔍 L2 Initial Triage & Workflow

The L2 analyst's role is to quickly validate the alert, gather necessary context, and escalate confirmed or suspicious activity.

### 1.1 Context Gathering
* Confirm with IT / platform owners whether any **legitimate usage** of `wmic.exe` is expected (common for admin scripting, inventory).
* **Baseline Knowledge**: Malicious use often involves querying user accounts, network settings, or deleting critical data.
* Validate the alert's time, host, and user against scheduled **maintenance or change windows**.

### 1.2 Data Collection
Gather the following essential forensic data and context:
* Full **command line** executed for `wmic.exe`. **Critical malicious commands/keywords to note**:
    * **Lateral/Execution**: `process call create`, `/node:`, `/user:`, `/password:`
    * **Evasion**: `shadowcopy delete` (T1490), `delete from __EventFilter`
    * **Reconnaissance**: `useraccount get`, `os get`, `netuse get`
* **Parent and first-level children** processes.
* Any other related security **alerts** on same host/user in the last 7 days.

### 1.3 Escalation
* If the command line involves **`process call create`**, **`shadowcopy delete`**, or contains a **remote URL** (via XSL) or **credential parameters** (`/user:`), immediately:
    * Flag the case with a **`LOLBIN-WMIC`** tag.
    * **Assign to L3** for high-priority investigation.

---

## 2. 🛡️ L3 Threat Investigation & Analysis

The L3 analyst's role is to perform a deep-dive analysis, determine the scope of compromise, and confirm the threat actor's intent.

### 2.1 Threat Assessment (Attack Vectors)
Determine if this is **Recon**, **Lateral Movement (T1021.006)**, **Execution**, or **Defense Evasion (T1490)**.
* **Key Focus: Lateral Movement**: If the command uses the `/node:` parameter, immediately pivot to investigate the target node.
* **Key Focus: Execution/Evasion**: Investigate `shadowcopy delete` or the use of the `XSL` flag to execute remote scripts.
* **Correlated Activity**: Look for sequential commands indicating hands-on-keyboard activity.

### 2.2 Evidence Collection (Deep Dive)
Capture and export critical data for preservation and reverse engineering:
* Export relevant process, file, and network records.
* **Network Analysis**: If `/node:` was used, capture the network session details between the source and target machine.
* **XSL Execution**: If a remote XSL was referenced, attempt to retrieve the remote XSL file.
* Capture memory / disk images as per SOPs for high-severity cases.

### 2.3 Cross-Environment Hunt (Threat Hunting)
Proactively hunt for similar activity across the environment to confirm or rule out a wider compromise:
* Hunt for the **process call create** command across the entire environment.
* Hunt for **shadowcopy deletion** attempts on servers/critical endpoints.
    ```kql
    // KQL Hunt: Malicious Execution or Evasion via wmic.exe
    DeviceProcessEvents
    | where FileName =~ "wmic.exe"
    | where ProcessCommandLine has_any (
        // Lateral Movement / Execution (Remote Process Call)
        "process call create", 
        "/node:", 
        "/user:", 
        // Evasion (Shadow Copy Deletion - Ransomware Precursor)
        "shadowcopy delete",
        // Remote Execution via XSL
        "xsl:"
    )
    | where InitiatingProcessFileName !in ("known_management_agents", "SCCM_agent.exe") // Filter known, high-volume automation
    | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
    ```

---

## 3. 🚧 Containment (Advanced)

Immediate actions to stop the threat actor and prevent further lateral spread.

* **Isolate affected endpoints**.
* **Reset or revoke credentials** linked to the account(s) involved. **Prioritize credentials used in the `/user:` argument.**
* Block identified malicious domains, IPs and hashes.
* **LATERAL PIVOT**: If lateral movement was confirmed (via `/node:`), immediately isolate the **target machine(s)**.
* If **shadowcopy delete** was confirmed, treat the event as a confirmed pre-ransomware step.

---

## 4. 📈 Remediation & Hardening (Strategic Actions)

Long-term actions to restore security, prevent recurrence, and improve detection capabilities.

### 4.1 Security Configuration Hardening
* **EOL of WMIC**: `wmic.exe` is deprecated. **Phase out and block `wmic.exe`** execution entirely if possible.
* **Constrain Execution**:
    * **AppLocker/WDAC**: Implement policies to block `wmic.exe` execution from user-writeable directories or from spawning suspicious child processes (e.g., downloading tools or malicious scripts).
* **Monitoring Alternatives**: Ensure detection coverage is strong for similar malicious commands run via **`cim.exe`** or **`Invoke-WmiMethod`**.

### 4.2 Detection Improvement
* Add this specific scenario to:
    * **Playbooks** for training and simulation.
    * **Regression tests** for detection content, focusing on catching the **`process call create`** and **`shadowcopy delete`** commands.

### 4.3 Policy Review
* Review whether upstream controls (email, web, identity) could be tuned to catch the intrusion earlier.
