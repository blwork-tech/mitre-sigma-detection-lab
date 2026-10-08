# MITRE ATT&CK Coverage Matrix

## Project Overview

This project contains six Sigma detection rules developed for Windows endpoint security monitoring.

Each rule is mapped to MITRE ATT&CK and validated using Windows Security or Sysmon event telemetry.

## Detection Coverage Matrix

| Rule ID | Detection | MITRE ATT&CK | Tactic | Data Source | Local Test |
|---|---|---|---|---|---|
| DET-001 | PowerShell Execution | T1059.001 | Execution | Sysmon Event ID 1 | PASS |
| DET-002 | Windows Command Shell | T1059.003 | Execution | Sysmon Event ID 1 | PASS |
| DET-003 | Failed Authentication | T1110.001* | Credential Access | Security Event ID 4625 | PASS |
| DET-004 | Local Account Creation | T1136.001 | Persistence | Security Event ID 4720 | PASS |
| DET-005 | Local Group Membership Change | T1098.007 | Persistence / Privilege Escalation | Security Event ID 4732 | PASS |
| DET-006 | PowerShell Network Connection | T1059.001 | Execution | Sysmon Event ID 3 | PASS |

*DET-003 identifies individual failed authentication events. A stronger password-guessing detection requires correlation of repeated failures.

## Validation Summary

- Sigma rules developed: 6
- Sigma YAML syntax checks: 6 passed
- Splunk SPL conversions: 6 successful
- Exported Windows events: 1,679
- Events matching local detection conditions: 28
- Detection conditions with at least one match: 6/6

## ATT&CK Coverage Limitations

1. The rules detect observable security behaviors, not necessarily malicious actions.
2. PowerShell and Command Shell detections may generate false positives during legitimate administration.
3. The failed authentication rule requires correlation logic to confidently identify password guessing.
4. Local account creation and group membership changes require administrative context.
5. Network activity initiated by PowerShell does not automatically imply command-and-control activity.

## Validation Scope

Windows telemetry was collected and inspected using Event Viewer.

Sigma YAML files passed syntax validation and were successfully converted to Splunk SPL.

A Python evaluator confirmed matches against the exported Windows event data.

The generated SPL queries have not yet been executed in a live SIEM.

## Future Improvements

- Deploy detections in a SIEM.
- Add authentication failure correlation.
- Test benign and suspicious datasets.
- Measure false-positive rates.
- Expand ATT&CK technique coverage.
