# curl.exe Attack Chain Context

## 1. Generic Execution Graph

```text
Initial Access (phishing / web / supply chain)
    ↓
User‑facing process (WINWORD.EXE / EXCEL.EXE / OUTLOOK.EXE / browser)
    ↓
Loader / script stage (powershell.exe / wscript.exe / cscript.exe / mshta.exe)
    ↓
curl.exe invoked with attacker‑controlled arguments
    ↓
Payload staging (download / decode / file drop / registry staging / in‑memory load)
    ↓
Post‑exploitation (credentials, lateral movement, C2, data collection, exfiltration)
```

This is a reasoning model, not a step‑by‑step how‑to. The goal is to understand
where curl.exe usually appears in relation to other technique categories.

## 2. Table Pivots by Phase

- **Initial access**
  - `EmailEvents`, `UrlClickEvents` if MDO data is available.
  - Proxy / firewall tables in Sentinel where integrated.

- **Loader and LOLBIN stage**
  - `DeviceProcessEvents`:
    - Office or browser spawning loaders, scripts, or directly spawning curl.exe.
  - `DeviceFileEvents`:
    - Dropped documents, scripts, or archives.

- **Payload staging**
  - `DeviceFileEvents`:
    - Executable / DLL / script writes in suspicious paths.
  - `DeviceRegistryEvents`:
    - Persistence keys (Run, RunOnce, services, COM).

- **Post‑exploitation**
  - `DeviceNetworkEvents`:
    - C2 channels, lateral connections, exfil paths.
  - `DeviceProcessEvents`:
    - Credential access, tunnelling, compression.

## 3. L3 Reasoning

The analyst should:

- Decide whether curl.exe is:
  - The first clearly malicious step,
  - Or merely a mid‑chain pivot.
- Evaluate whether upstream controls should have prevented earlier stages.
- Use this insight to:
  - Seed new hunts across the estate,
  - Propose control improvements,
  - Prioritise engineering backlog items.
