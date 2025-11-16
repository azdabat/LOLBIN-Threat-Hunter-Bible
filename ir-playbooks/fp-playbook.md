# IR Playbook – fp.exe

## 1. L2 Workflow

- Confirm with IT / platform owners whether any legitimate usage of fp.exe is expected.
- Validate time, host, and user against scheduled maintenance or change windows.
- Gather:
  - Full command line for fp.exe.
  - Parent and first‑level children.
  - Any other alerts on same host/user in the last 7 days.
- Flag the case with a `LOLBIN-FP` tag and assign to L3.

## 2. L3 Workflow

1. **Threat assessment**
   - Determine if this is opportunistic malware, targeted intrusion, or benign admin noise.
   - Look for:
     - Multiple tactics present (execution + persistence + lateral + C2).
     - Signs of hands‑on‑keyboard.

2. **Evidence collection**
   - Export relevant process, file, network records.
   - Capture payloads where possible for reverse engineering.
   - Capture memory / disk images as per local SOPs for high‑severity cases.

3. **Cross‑environment hunt**
   - Hunt for:
     - Reuse of command fragments and infra.
     - Similar activity across hosts, users, and business units.

## 3. Containment

- Isolate affected endpoints where malicious activity is confirmed or strongly suspected.
- Reset or revoke credentials linked to the account(s) involved.
- Block identified malicious domains, IPs and hashes at relevant controls.

## 4. Remediation & Hardening

- Where feasible, constrain usage of fp.exe to specific contexts via:
  - AppLocker, WDAC, or third‑party application control.
- Add this scenario to:
  - Playbooks for training and simulation.
  - Regression tests for detection content.
- Review whether upstream controls (email, web, identity) could be tuned to catch
  this intrusion earlier.
