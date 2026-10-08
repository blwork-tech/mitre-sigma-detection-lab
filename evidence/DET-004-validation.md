# DET-004: Windows Local Account Creation

**Objective:** Identify Windows account creation events using a Sigma detection rule.

**MITRE ATT&CK:** T1136.001 — Create Account: Local Account  
**Tactic:** Persistence  
**Telemetry:** Windows Security Event ID 4720

## Test Procedure

1. Confirmed that Windows account-management success auditing was enabled.
2. Created a standard local test account named `DetectionLabTest`.
3. Inspected Windows Security logs for Event ID 4720.
4. Checked the event details against the Sigma selection criteria.

## Expected Result

Windows generates Event ID 4720 when the local test account is created.

## Actual Result

[Record event timestamp, account name, and observed details.]

## Validation Results

- YAML syntax: Not yet verified
- Windows event generation: Not yet verified
- Sigma detection execution: Not yet verified

## False Positives

Legitimate account provisioning, IT administration, and automated software account creation.

## Limitations

Event ID 4720 identifies account creation but does not independently establish malicious activity. Additional context is necessary to determine whether the action was authorized.

## Recommendations

Correlate account creation events with subsequent privileged-group membership changes, such as Windows Security Event ID 4732. Review which administrator initiated the action and whether account creation was expected.