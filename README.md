# LOLBins Detection & Hunting Framework  
Author: Ala Dabat  
Version: 2025-11  
Status: Active Development

---

## Overview

This section contains a growing collection of production-grade detection rules focused on identifying abuse of Windows Living-off-the-Land Binaries (LOLBins). These rules are built for Microsoft Defender for Endpoint and Sentinel, using behaviour-first logic, attacker tradecraft patterns, parent/child process lineage, and contextual scoring.

The goal is simple: expose the execution chains and persistence mechanisms adversaries rely on while blending into legitimate activity.

Rules in this section cover:

- Rundll32 abuse (payload loading, encoded commands, remote DLLs)  
- Regsvr32 abuse (COM hijacks, scriptlet execution, downloader patterns)  
- Bitsadmin misuse (file transfer, payload staging, masquerading)  
- Certutil misuse (download, decode, anonymised transfer)  
- Mshta, Wscript, Cscript, Powershell downgrade and encoded modes  
- DLL/driver sideloading and hijacking  
- Process hollowing indicators  
- Registry-based LOLBin staging  
- Network-driven payload retrieval  

Each rule includes:

- Full KQL or MDE hunting query  
- MITRE ATT&CK mapping  
- Severity and scoring heuristic  
- Analyst investigation workflow  
- HuntingDirectives field for SOC L2–L3  
- Clear detection notes and operational context  

---

## Project Status

This repository is actively being expanded.  
Rules are continuously tuned against real attacker behaviours, threat-hunting simulations, and supply-chain style intrusion chains.

New rules are added weekly, and existing rules receive revisions based on:

- Telemetry quality  
- Noise reduction  
- Fidelity improvements  
- Additional MITRE coverage  
- Integration with the broader supply-chain and persistence detection framework  

---

## Current Functionality

Most of the core LOLBin rules are fully operational and aligned with production-level detection expectations. Any remaining placeholders are being replaced as additional stages—persistence, credential access, and post-exploitation—are finalised.

If you encounter gaps or want to request a specific LOLBin detection, open an issue or pull request.

---

## Structure

Recommended repository layout:


