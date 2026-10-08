# Windows Sigma Detection Engineering Lab

**Portfolio project | Windows 11 • Sysmon • Sigma • MITRE ATT&CK**

## Executive summary
This repository documents six experimental Windows security detections written in Sigma, with MITRE ATT&CK mapping, safe test scenarios, and a reproducible evidence/validation workflow. The project demonstrates how a detection engineer moves from **telemetry → detection logic → ATT&CK context → validation → tuning recommendations**.

> **Status:** Rule pack drafted. Individual event collection, syntax checks, SIEM conversion, and detection execution must be recorded in the validation files before being claimed as completed.

## Architecture
macOS host
  └── VirtualBox Windows 11 VM
       ├── Sysmon: Event IDs 1, 3
       ├── Windows Security: Event IDs 4625, 4720, 4732
       └── Windows Event Viewer / Get-WinEvent (source verification)
                 │
                 ▼
            Sigma YAML rules
                 │
                 ▼
         Sigma CLI syntax checks
                 │
                 ▼
      Optional backend query conversion
                 │
                 ▼
        Detection-engine validation
```

**Important:** Sigma is a portable detection-rule format, not an event collector or a SIEM. Looking up events in Event Viewer proves the source telemetry exists;
it does **not** prove that the Sigma rule executed or fired.

## Rule inventory
| ID      | Detection             | Primary event | ATT&CK context |
| DET-001 | PowerShell Process Execution | Sysmon 1 | T1059.001 |
| DET-002 | Windows Command Shell Execution | Sysmon 1 | T1059.003 |
| DET-003 | Windows Failed Logon Event | Security 4625 | T1110.001 (context; not a brute-force detector) |
| DET-004 | Windows Account Creation Event | Security 4720 | T1136.001 (standalone VM test) |
| DET-005 | Member Added to Local Security Group | Security 4732 | T1098.007 |
| DET-006 | PowerShell Network Connection | Sysmon 3 | T1059.001 (context; not a C2 detector) |

See [coverage/mitre-coverage.md](coverage/mitre-coverage.md) for the tracking matrix.

## Repository structure
mitre-sigma-detection-lab/
├── README.md
├── rules/                      # Six Sigma YAML detections
├── docs/                       # Setup guide and methodology
├── coverage/mitre-coverage.md  # ATT&CK / evidence matrix
├── validation/                 # Six per-rule validation templates
├── evidence/screenshots/      # Add redacted proof screenshots
└── presentation/              # Presentation outline

## Quick start

1. Run the Windows 11 lab VM in VirtualBox with appropriate local permissions.
2. Enable Sysmon Event ID 1 and optionally Event ID 3; ensure Windows Security auditing is configured for account events.
3. Generate harmless laboratory actions described in each `validation/DET-00x.md` file.
4. Verify the relevant source log using Event Viewer or `Get-WinEvent`.
5. Install Sigma CLI in the environment where Python is available, then run `sigma check rules/` (adjust path/syntax to your installed CLI version).
6. Optionally install a compatible Sigma backend and convert rules to your SIEM's query language.
7. Run converted detections in a compatible detection engine against lab data; save queries and actual hits before marking that check as PASS.

## What has and hasn't been demonstrated

- **Authored:** Six proposed rules and validation plans.
- **Needs independent verification:** YAML checks, observed Windows events, conversion results, and executed rule matches.
- **Not claimed:** Production-grade detection quality, tested true-positive rate, actual intrusion detection, or full ATT&CK coverage.

## Design caveats

- DET-001 and DET-002 detect common shells, not suspicious usage by themselves.
- DET-003 detects **one failed authentication event**. Brute-force/password guessing requires correlation of multiple failures.
- DET-004's Event ID 4720 also occurs in some domain account creation scenarios; the local interpretation is based on the standalone lab.
- DET-005's Event ID 4732 can include routine group changes; distinguish privileged and nonprivileged groups.
- DET-006 needs Sysmon Event ID 3 network connection logging enabled, a working network path, and process-attributed events. It does not independently prove command and control.

## AI-assisted workflow and quality controls
AI assistance was used to draft rule ideas and documentation. ATT&CK technique mappings should be checked against MITRE ATT&CK, and logging behavior against Microsoft and Sigma references. No AI-generated detection claim should be treated as validated without test evidence.

## Responsible lab use
All tests are designed for an owned, isolated Windows VM and user-created test accounts. Do not scan third-party networks or upload sensitive event logs, credentials, or personal identifiers to a public repository.

## References
- [Sigma documentation](https://sigmahq.io/docs/)
- [Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
