# LOLBIN Detection Strength Overview

| LOLBIN    | Binary        | Detection Strength | Notes                                                |
|---------- |-------------- |------------------- |----------------------------------------------------- |
| certutil  | certutil.exe  | High               | Rare on endpoints; strong signal when baselined.    |
| mshta     | mshta.exe     | High               | Rare in modern estates; good early indicator.       |
| rundll32  | rundll32.exe  | Medium             | Very common; heavy context required.                |
| regsvr32  | regsvr32.exe  | Medium             | Used legitimately; scriptlet abuse stands out.      |
| powershell| powershell.exe| Medium             | Ubiquitous; deep tuning needed.                     |
| wscript   | wscript.exe   | Medium             | Legacy-heavy; look for rare parents.                |
| cscript   | cscript.exe   | Medium             | Similar to wscript; console usage is rarer.         |
| bitsadmin | bitsadmin.exe | High               | Deprecated; almost always suspicious now.           |
| installutil|installutil.exe| High              | Rare outside .NET install; good anchor.             |
| curl      | curl.exe      | Medium             | Increasingly common; parent/path context critical.  |
| schtasks  | schtasks.exe  | Medium             | Admin-heavy; pair with child processes.             |
| vssadmin  | vssadmin.exe  | High               | Strong ransomware pre-stage signal.                 |
| wevtutil  | wevtutil.exe  | High               | Strong anti-forensics indicator.                    |
| dnscmd    | dnscmd.exe    | High               | Server-side only; highly meaningful.                |
| forfiles  | forfiles.exe  | Medium             | Needs coupling with child binaries.                 |
| cmstp     | cmstp.exe     | High               | Strong signal on endpoints.                         |
| esentutl  | esentutl.exe  | Medium             | Focus on data/credential stores.                    |
| wmic      | wmic.exe      | Medium             | Legacy; focus on remote targets.                    |
| fp        | fp.exe        | Low                | Niche; treat as bespoke.                            |
