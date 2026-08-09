from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List
import re

app = FastAPI()


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Dict[str, Any]
    image: Dict[str, Any]


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations: List[str] = []

    workflow = req.workflow
    image = req.image

    # ---------------------------------------------------------
    # 1. Permissions must be EXACTLY least privilege
    # ---------------------------------------------------------
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull request trigger
    # ---------------------------------------------------------
    #
    # If this is a PR event, only pull_request is allowed.
    # pull_request_target is always unsafe.
    #
    if req.event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    elif workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Tests / matrix / fail-fast
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. Action pinning
    # ---------------------------------------------------------
    #
    # actions/* may use tags.
    # Every third-party action must use a lowercase
    # 40-character hexadecimal SHA.
    #
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")

    for action in workflow.get("actions", []):
        owner = action.get("owner")
        ref = action.get("ref")

        if owner != "actions":
            if not isinstance(ref, str) or not sha_pattern.fullmatch(ref):
                violations.append("MUTABLE_ACTION")
                break

    # ---------------------------------------------------------
    # 5. Multi-stage image
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # ---------------------------------------------------------
    # 6. Non-root runtime
    # ---------------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # ---------------------------------------------------------
    # 7. Build secrets
    # ---------------------------------------------------------
    #
    # Allowed:
    #   none
    #   buildkit
    #
    # Not allowed:
    #   arg
    #   copy
    #
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # ---------------------------------------------------------
    # 8. Critical vulnerabilities
    # ---------------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # ---------------------------------------------------------
    # 9. Digest-pinned image
    # ---------------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 10. Production requirements
    # ---------------------------------------------------------
    if req.target == "production":

        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # Final decision
    # ---------------------------------------------------------
    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations,
    }