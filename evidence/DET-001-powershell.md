# DET-001 - PowerShell Execution

## Objective
Detect PowerShell process execution on a Windows endpoint.

## Data Source
Sysmon Process Creation telemetry.

## MITRE ATT&CK
T1059.001 - PowerShell
Tactic: Execution

## Test
Opened PowerShell and executed a harmless Write-Host command.

## Expected Result
A process creation event containing powershell.exe.

## Actual Result
PowerShell process creation was observed in Sysmon telemetry.

## Result
PASS

## False Positives
- System administration
- Developer activity
- Management scripts

## Limitation
This rule detects PowerShell usage, not necessarily malicious PowerShell behavior.

## Future Improvement
Add command-line and parent-process context to increase detection fidelity.