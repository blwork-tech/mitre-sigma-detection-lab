# DET-002 - Windows Command Shell Execution

## Objective
Detect execution of the Windows Command Shell.

## Data Source
Sysmon Process Creation telemetry.

## MITRE ATT&CK
T1059.003 - Windows Command Shell
Tactic: Execution

## Test
Opened Command Prompt and executed harmless commands including
whoami and echo.

## Expected Result
A process creation event containing cmd.exe.

## Actual Result
cmd.exe process creation was observed in Sysmon telemetry.

## Result
PASS

## False Positives
- System administration
- User troubleshooting
- Software installation
- Automated scripts

## Limitation
The rule detects use of cmd.exe and does not by itself indicate
malicious behavior.

## Future Improvement
Add parent-process and command-line conditions to detect more
suspicious command-shell activity while reducing false positives.