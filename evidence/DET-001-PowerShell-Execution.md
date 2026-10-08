## DET-001 PowerShell Execution

Objective
Detect PowerShell process creation.

MITRE ATT&CK
T1059.001 — PowerShell
Tactic: Execution

Telemetry
Sysmon Process Create

Test
Opened PowerShell within the isolated Windows lab and
executed a harmless console command.

Expected Result
Process telemetry identifying powershell.exe.

Actual Result
Matching event observed.

Detection Result
PASS

False Positive Considerations
- System administration
- Developer activity
- Management scripts

Limitations
The rule detects PowerShell usage rather than malicious
PowerShell behavior and therefore requires further tuning.

Recommendation
Add command-line and parent-process context to improve
signal quality.