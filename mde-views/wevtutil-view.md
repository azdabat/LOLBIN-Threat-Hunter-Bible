# MDE View – wevtutil.exe

## 1. Expected Surfacing

Depending on configuration, wevtutil.exe abuse may surface as:

- A built‑in behavioural alert.
- A low/medium severity alert tied to suspicious process behaviour.
- Only an Advanced Hunting hit from this rulepack.

The rulepack assumes **you cannot rely** on built‑in alerts alone and uses
Advanced Hunting as the primary detection surface.

## 2. Typical Analyst View

An analyst starting from this rule will see:

- Host: `DeviceName`, OS, risk indicators.
- User: `AccountName`, enrichment from identity sources.
- Process:
  - `FileName = wevtutil.exe`
  - Parent image and parent command line.
  - Full child chain via further queries.

Key questions:

- Is wevtutil.exe ever legitimately used on this workstation/server?
- Does this align with documented admin behaviour?
- Are there any parallel alerts on the same host or user?

## 3. L3 Action List

1. **Contextualise host and user**
   - Is the host critical (domain controller, finance, OT, jump box)?
   - Is the user an admin, executive, or service account?

2. **Rebuild execution**
   - Pull surrounding `DeviceProcessEvents` and visualise the process tree.
   - Mark clearly malicious children (credential tools, remote shells, compression tools).

3. **Correlate infrastructure**
   - Pivot to `DeviceNetworkEvents`.
   - Check outbound infra against CTI.
   - Identify any reuse across other incidents.

4. **Scope the incident**
   - Run parameterised hunts for:
     - Same commandline fragments.
     - Same parent/child combos.
     - Same remote infrastructure.
