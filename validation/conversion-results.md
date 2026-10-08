# Sigma to Splunk Conversion Results
Date: 2026-10-07

## DET-001
```spl
EventID=1 Image IN ("*\\powershell.exe", "*\\pwsh.exe")

```

## DET-002
```spl
EventID=1 Image="*\\cmd.exe"

```

## DET-003
```spl
source="WinEventLog:Security" EventCode=4625

```

## DET-004
```spl
source="WinEventLog:Security" EventCode=4720 | table TargetUserName,SubjectUserName,TargetSid,SubjectLogonId

```

## DET-005
```spl
source="WinEventLog:Security" EventCode=4732

```

## DET-006
```spl
EventID=3 Image IN ("*\\powershell.exe", "*\\pwsh.exe")

```

