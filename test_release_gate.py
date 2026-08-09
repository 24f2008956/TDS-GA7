import json
import urllib.request

payload = {
    "target": "preview",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {
                "owner": "actions",
                "name": "checkout",
                "ref": "v4"
            }
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}

request = urllib.request.Request(
    "http://127.0.0.1:8000/release-gate",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)

with urllib.request.urlopen(request) as response:
    result = json.load(response)

print(json.dumps(result, indent=2))

assert result["decision"] == "promote"
assert result["violations"] == []