
import json
from pathlib import Path

LOG_DIR = Path("evidence/exported-logs")

def load_events(filename):
    path = LOG_DIR / filename
    return json.loads(path.read_text(encoding="utf-8-sig"))

sysmon = load_events("sysmon-events.json")
security = load_events("security-events.json")

def image_endswith(event, names):
    image = str(event.get("Fields", {}).get("Image", "")).lower()
    return any(image.endswith(name.lower()) for name in names)

tests = {
    "DET-001 PowerShell Execution": [
        e for e in sysmon
        if int(e["EventID"]) == 1
        and image_endswith(e, ["\\powershell.exe", "\\pwsh.exe"])
    ],
    "DET-002 Command Shell": [
        e for e in sysmon
        if int(e["EventID"]) == 1
        and image_endswith(e, ["\\cmd.exe"])
    ],
    "DET-003 Failed Logon": [
        e for e in security if int(e["EventID"]) == 4625
    ],
    "DET-004 Account Creation": [
        e for e in security if int(e["EventID"]) == 4720
    ],
    "DET-005 Group Membership Change": [
        e for e in security if int(e["EventID"]) == 4732
    ],
    "DET-006 PowerShell Network Connection": [
        e for e in sysmon
        if int(e["EventID"]) == 3
        and image_endswith(e, ["\\powershell.exe", "\\pwsh.exe"])
    ],
}

print("\n=== DETECTION LAB VALIDATION ===\n")

for name, matches in tests.items():
    result = "MATCH" if matches else "NO MATCH"
    print(f"{name}: {result} ({len(matches)} events)")

print("\nNote: This tests equivalent event-field conditions.")
print("It does not execute the Sigma YAML or Splunk SPL.")
