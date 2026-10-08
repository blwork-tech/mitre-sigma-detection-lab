# DET-003 - Windows Failed Logon

## Objective
Detect failed Windows authentication attempts.

## Data Source
Windows Security Event Log.

## Event
Event ID 4625 - An account failed to log on.

## MITRE ATT&CK
T1110.001 - Password Guessing
Tactic: Credential Access

## Test
Attempted to authenticate to a laboratory test account using an
incorrect password.

## Expected Result
Windows generates Security Event ID 4625.

## Actual Result
Event ID 4625 was observed in the Windows Security log.

## Detection Result
PASS

## False Positives
- Mistyped passwords
- Forgotten passwords
- Expired credentials
- Applications using outdated credentials
- Misconfigured service accounts

## Limitation
A single failed authentication event does not indicate password
guessing or malicious activity.

The current Sigma rule detects individual failed authentication
events. A higher-confidence production detection would correlate
multiple failures involving the same account, source, or host
within a defined time period.

## Future Improvement
Implement correlation logic to detect repeated authentication
failures over time and assign a higher severity when a threshold
is reached.