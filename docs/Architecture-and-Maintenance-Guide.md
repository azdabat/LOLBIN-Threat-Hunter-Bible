# 📚 Architecture & Maintenance Guide – LOLBIN Threat Hunter Bible (For Senior SOC/TI Roles)

This document describes the foundational architecture, design principles, and operational maintenance guide for the **LOLBIN Threat Hunter Bible** rulepack. This project is intended to serve as a production-grade detection and response framework for known Living Off the Land Binary (LOLBIN) abuse, tailored for mature Security Operations Center (SOC) and Detection Engineering (DE) functions.

---

## 1. 🎯 Strategic Objectives

This repository is structured to demonstrate senior-level mastery across the defensive security lifecycle, providing tangible artifacts for hiring managers to evaluate:

* **Production-Grade Hunting Logic**: Deliver highly precise, low-false-positive **KQL (Kusto Query Language)** logic optimized for **Microsoft Defender for Endpoint (MDE)** and **Microsoft Sentinel**.
* **Consistent Investigation Doctrine**: Establish standardized, high-detail **L2 $\rightarrow$ L3** workflows and playbooks that ensure consistent, rapid, and effective incident response.
* **Detection-as-Code (DaC)**: Provide deployable YAML definitions for Sentinel Analytic Rules, showcasing automation and infrastructure expertise.
* **Threat Intelligence Integration**: Map all detection logic directly to the **MITRE ATT&CK Framework**, providing context on prevalence and adversary tradecraft.
* **Seniority Evaluation**: Serve as a portfolio artifact demonstrating expertise in platform utilization (MDE/Sentinel), advanced query writing, risk scoring, and strategic hardening.

---

## 2. 🗺️ Repository Content Model and Rationale

The repository structure is logical, mirroring the progression from threat intelligence to deployment and operational response.

| Directory | Core Content | L3 Analyst / TI Value Proposition |
| :--- | :--- | :--- |
| `rules/` | KQL hunting queries (`.kql`), rationale, and false positive analysis per LOLBIN. | Demonstrates **advanced query optimization** and understanding of telemetry noise. |
| `attack-chains/` | Detailed narratives/diagrams describing multi-stage attacks (e.g., MSHTA $\rightarrow$ PowerShell $\rightarrow$ BITSAdmin). | Shows competence in **kill-chain analysis** and identifying high-fidelity multi-stage behaviors. |
| `mde-views/` | Custom MD/JSON views for the MDE Advanced Hunting schema. | Exhibits **platform-specific expertise** and ability to craft custom interfaces for operational efficiency. |
| `ir-playbooks/` | L2 $\rightarrow$ L3 investigation workflows, containment steps, and strategic remediation. | Proves ability to design and govern **effective IR processes** and procedures. |
| `sentinel-rules/` | YAML definitions for Analytic Rules wrapping the hunting KQL. | Confirms ability to implement **Detection-as-Code (DaC)** principles for automated deployment. |
| `tables/` | Mitigation mapping, pivot guides, and a detailed **Detection Strength Matrix**. | Shows **strategic risk assessment** skills and understanding of defense-in-depth gaps. |

---

## 3. 🛠️ Operational Maintenance Guide (L3 Focus)

A strong L3 or Threat Intel candidate must demonstrate how content is maintained in a dynamic threat landscape.

### 3.1. 🔁 The Detection Lifecycle (Develop $\rightarrow$ Deploy $\rightarrow$ Tune)

1.  **Develop (Threat Research)**: A new adversary technique is identified (e.g., via CISA/Mandiant reports) that abuses a known LOLBIN (e.g., `cmd.exe`).
    * **Action**: Create or update the relevant file in `rules/` with a high-precision KQL query, focusing on behavioral anomalies (e.g., `cmd.exe` spawning from an Office application with network traffic).
2.  **Test & Validate (Tuning)**: The KQL is run in MDE's Advanced Hunting.
    * **Action**: Analyze false positives (FPs). Add relevant exclusions (e.g., specific management agent processes) directly into the KQL comment block. Update the **false positive rationale** in the `rules/` file.
3.  **Deploy (Automation)**: The stable KQL is wrapped for deployment.
    * **Action**: Create the corresponding YAML definition in `sentinel-rules/`, ensuring the query uses the appropriate time frame and scheduling, and correctly assigns **MITRE Tactics** and **Entities** for incident creation.
4.  **Review (IR Feedback)**: An L2/L3 analyst handles an incident triggered by the new rule.
    * **Action**: If the IR Playbook failed to contain the threat or the rule created persistent noise, feedback must be used to update both the **KQL** (step 1) and the **`ir-playbooks/`** (step 5).

### 3.2. 📈 Metrics and Strategic Prioritization

Senior analysts must prioritize detection efforts based on risk and effort.

| Metric | Rationale | `tables/` Artifacts |
| :--- | :--- | :--- |
| **Detection Strength** | Rates the rule's fidelity (High, Medium, Low) and its risk of false positives. High fidelity rules are prioritized for Sentinel automation. | Detection Strength Matrix |
| **Mitigation Gaps** | Identifies which LOLBIN techniques are **not** fully blocked by preventative controls (e.g., AppLocker/WDAC) and thus require immediate detection rules. | MITRE Mapping Table |
| **Coverage Quality** | Tracks the percentage of active, real-world attack chains covered by the current rule set. | `attack-chains/` documentation |

### 3.3. 🗃️ Code Integrity and Versioning

* **Rule Rationale**: Every KQL file in `rules/` must include a detailed header explaining: **Adversary Technique (MITRE ID)**, **Expected Parent/Child Relationship**, and **FP Exclusion Rationale**.
* **Version Control**: All changes must be made via **Pull Requests (PRs)** with clear, concise descriptions detailing the reason for the change (e.g., "Tuning: Added FP exclusion for SCCM agent to `bitsadmin.kql`").
* **WDAC/AppLocker Integration**: Rules in the `rules/` directory must include a section on the recommended **WDAC/AppLocker policy** required to prevent the execution entirely, demonstrating competence in preventative hardening.

---

## 4. 📝 Conclusion

This **LOLBIN Threat Hunter Bible** represents a mature, integrated approach to threat hunting and detection engineering. By combining platform-specific technical execution (KQL, MDE views) with strategic governance (IR Playbooks, DaC YAML, MITRE mapping), this project serves as tangible evidence of the skills required for senior-level roles in modern security organizations.
