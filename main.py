from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List
import re

import re
import html
from urllib.parse import unquote, urlsplit
from fastapi import Request

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

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List
import re

app = FastAPI()

ASSIGNED_TENANT = "tenant-lqccake"
ALLOWED_EMAIL_DOMAIN = "notify-dm117fp.example"


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Dict[str, Any]
    image: Dict[str, Any]


class ActionFirewallRequest(BaseModel):
    provenance: str
    humanApproved: bool
    untrustedContent: str | None = None
    action: Dict[str, Any]


def firewall_result(decision: str, reason: str):
    return {
        "decision": decision,
        "reason": reason
    }


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations: List[str] = []

    workflow = req.workflow
    image = req.image

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    if req.event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")
    elif workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    sha_pattern = re.compile(r"^[0-9a-f]{40}$")

    for action in workflow.get("actions", []):
        if action.get("owner") != "actions":
            ref = action.get("ref")
            if not isinstance(ref, str) or not sha_pattern.fullmatch(ref):
                violations.append("MUTABLE_ACTION")
                break

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if req.target == "production":
        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.post("/action-firewall")
def action_firewall(req: ActionFirewallRequest):

    # ---------------------------------------------------------
    # 1. Top-level schema
    # ---------------------------------------------------------

    if req.provenance not in ("trusted", "untrusted"):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(req.humanApproved, bool):
        return firewall_result("block", "INVALID_SCHEMA")

    if req.untrustedContent is not None and not isinstance(
        req.untrustedContent, str
    ):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(req.action, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    if "tool" not in req.action or "args" not in req.action:
        return firewall_result("block", "INVALID_SCHEMA")

    tool = req.action["tool"]
    args = req.action["args"]

    if not isinstance(tool, str) or not isinstance(args, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    # ---------------------------------------------------------
    # 2. Tool allowlist
    # ---------------------------------------------------------

    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html",
    }

    if tool not in allowed_tools:
        return firewall_result("block", "TOOL_NOT_ALLOWED")

    # ---------------------------------------------------------
    # 3. Tool argument schemas
    # ---------------------------------------------------------

    if tool == "search":
        if (
            set(args.keys()) != {"query"}
            or not isinstance(args.get("query"), str)
            or not (1 <= len(args["query"]) <= 200)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":
        if (
            set(args.keys()) != {"tenantId", "recordId"}
            or not isinstance(args.get("tenantId"), str)
            or not isinstance(args.get("recordId"), str)
            or args["recordId"] == ""
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "send_email":
        if (
            set(args.keys()) != {"to", "subject", "body"}
            or not isinstance(args.get("to"), str)
            or not isinstance(args.get("subject"), str)
            or not isinstance(args.get("body"), str)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "render_html":
        if (
            set(args.keys()) != {"html"}
            or not isinstance(args.get("html"), str)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    # ---------------------------------------------------------
    # 4. Tenant scope
    # ---------------------------------------------------------

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return firewall_result("block", "TENANT_SCOPE")

    # ---------------------------------------------------------
    # 5. Egress restrictions
    # ---------------------------------------------------------

    if tool == "send_email":
        to = args["to"]

        if "@" not in to:
            return firewall_result("block", "EGRESS_DENIED")

        domain = to.rsplit("@", 1)[1]

        if domain != ALLOWED_EMAIL_DOMAIN:
            return firewall_result("block", "EGRESS_DENIED")

    # ---------------------------------------------------------
    # 6. Human approval
    # ---------------------------------------------------------

    if tool == "send_email":
        if req.humanApproved is not True:
            return firewall_result("block", "APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # 7. HTML safety
    # ---------------------------------------------------------

    if tool == "render_html":
        html = args["html"]

        unsafe_patterns = [
            r"<script\b",
            r"</script\s*>",
            r"<iframe\b",
            r"\bon[a-z]+\s*=",
            r"javascript\s*:",
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, html, flags=re.IGNORECASE):
                return firewall_result("block", "UNSAFE_OUTPUT")

    # ---------------------------------------------------------
    # 8. Allowed
    # ---------------------------------------------------------

    return firewall_result("allow", "ALLOW")

class TerraformPlanRequest(BaseModel):
    environment: str
    state: Dict[str, Any]
    providerVersion: str
    destroyApproved: bool
    resource: Dict[str, Any]


REQUIRED_LABELS = {
    "owner": "student-mitnf",
    "environment": "production",
    "cost_center": "cc-5zx9",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
STATEFUL_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


@app.post("/terraform/plan")
def terraform_plan(req: TerraformPlanRequest):

    # ---------------------------------------------------------
    # 1. Validate request and nested object types
    # ---------------------------------------------------------

    if not isinstance(req.environment, str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(req.state, dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(req.providerVersion, str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(req.destroyApproved, bool):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(req.resource, dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    # Required state types
    if (
        not isinstance(req.state.get("backend"), str)
        or not isinstance(req.state.get("locked"), bool)
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    resource = req.resource

    # Required resource fields/types
    if not isinstance(resource.get("address"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(resource.get("type"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(resource.get("action"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(resource.get("labels"), dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if resource.get("secret") is not None and not isinstance(
        resource.get("secret"), str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    if not isinstance(resource.get("forceDestroy"), bool):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    # Validate allowed action values
    if resource.get("action") not in {"create", "update", "delete"}:
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    # ---------------------------------------------------------
    # 2. Environment
    # ---------------------------------------------------------

    if req.environment != "prod-csr1mn":
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        }

    # ---------------------------------------------------------
    # 3. Remote state + locking
    # ---------------------------------------------------------

    if (
        req.state.get("backend") not in ALLOWED_BACKENDS
        or req.state.get("locked") is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        }

    # ---------------------------------------------------------
    # 4. Provider version pinning
    # ---------------------------------------------------------

    provider = req.providerVersion.strip()

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_provider_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        }

    # ---------------------------------------------------------
    # 5. Required labels
    # ---------------------------------------------------------

    labels = resource.get("labels")

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

    # ---------------------------------------------------------
    # 6. Secret handling
    # ---------------------------------------------------------

    secret = resource.get("secret")

    if secret is not None:
        if (
            not isinstance(secret, str)
            or not secret.startswith("secret://")
            or len(secret) <= len("secret://")
        ):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            }

    # ---------------------------------------------------------
    # 7. Destructive deletes
    # ---------------------------------------------------------

    if (
        resource.get("action") == "delete"
        and resource.get("type") in STATEFUL_DELETE_TYPES
        and req.destroyApproved is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # ---------------------------------------------------------
    # 8. Production storage bucket forceDestroy
    # ---------------------------------------------------------

    if (
        resource.get("type") == "storage_bucket"
        and resource.get("forceDestroy") is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        }

    # ---------------------------------------------------------
    # 9. Everything passed
    # ---------------------------------------------------------

    return {
        "decision": "approve",
        "reason": "APPROVE"
    }


# ============================================================
# Q4 - LLM Output Handling Gate (OWASP LLM05)
# ============================================================

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-wko562a.example",
    "app-koyam7o.example",
}

VALID_CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def decode_once(value: str) -> str:
    """
    Decode exactly once in this order:
    1. percent escapes
    2. specified HTML entities
    3. \\uXXXX escapes
    """

    # 1. Percent escapes
    decoded = unquote(value)

    # 2. HTML numeric entities and the five specified named entities
    def html_entity_replace(match):
        entity = match.group(0)

        if entity.startswith("&#x") or entity.startswith("&#X"):
            try:
                return chr(int(entity[3:-1], 16))
            except ValueError:
                return entity

        if entity.startswith("&#"):
            try:
                return chr(int(entity[2:-1], 10))
            except ValueError:
                return entity

        named = {
            "&lt;": "<",
            "&gt;": ">",
            "&quot;": '"',
            "&apos;": "'",
            "&amp;": "&",
        }

        return named.get(entity, entity)

    decoded = re.sub(
        r"&#x[0-9a-fA-F]+;|&#[0-9]+;|&lt;|&gt;|&quot;|&apos;|&amp;",
        html_entity_replace,
        decoded,
        flags=re.IGNORECASE,
    )

    # 3. Literal \uXXXX escapes
    def unicode_replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_replace,
        decoded,
    )

    return decoded


def contains_dangerous_scheme(text: str) -> bool:
    """
    Detect dangerous schemes appearing directly in text.
    """
    return bool(
        re.search(
            r"(?:javascript|data|vbscript)\s*:",
            text,
            flags=re.IGNORECASE,
        )
    )


def extract_urls(channel: str, output: str):
    """
    Extract URLs according to the channel-specific rules.
    """

    if channel == "html":
        # Only quoted src= and href= attributes
        pattern = r"""
            \b(?:src|href)
            \s*=\s*
            (?:
                "([^"]*)"
                |
                '([^']*)'
            )
        """

        urls = []

        for match in re.finditer(
            pattern,
            output,
            flags=re.IGNORECASE | re.VERBOSE,
        ):
            urls.append(match.group(1) if match.group(1) is not None else match.group(2))

        return urls

    if channel == "markdown":
        # Target inside ](...)
        pattern = r"\]\(([^)]*)\)"

        return [
            match.group(1).strip()
            for match in re.finditer(pattern, output)
        ]

    if channel == "url":
        return [output.strip()]

    return []


def url_has_dangerous_scheme(url: str) -> bool:
    """
    A URL is dangerous if its scheme is not http/https.
    Protocol-relative URLs are treated as https.
    Relative URLs are allowed.
    """

    value = url.strip()

    if value.startswith("//"):
        # Protocol-relative URL is treated as https
        return False

    parsed = urlsplit(value)

    # No scheme means relative reference
    if not parsed.scheme:
        return False

    return parsed.scheme.lower() not in {"http", "https"}


def url_is_external_exfil(url: str) -> bool:
    """
    Absolute URLs must have an exact allowed hostname.
    Relative references are allowed.
    """

    value = url.strip()

    # Protocol-relative URL is absolute
    if value.startswith("//"):
        parsed = urlsplit("https:" + value)
        return parsed.hostname not in ALLOWED_EXTERNAL_HOSTS

    parsed = urlsplit(value)

    # Relative URL
    if not parsed.scheme:
        return False

    # Only HTTP/HTTPS reaches this point.
    hostname = parsed.hostname

    if hostname is None:
        return True

    return hostname not in ALLOWED_EXTERNAL_HOSTS


def channel_violation(channel: str, output: str):
    """
    Apply channel rules in the required order.
    Returns the first violation or None.
    """

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------
    if channel == "html":

        # SCRIPT_TAG first
        if re.search(
            r"<\s*(script|iframe|object|embed)\b",
            output,
            flags=re.IGNORECASE,
        ):
            return "SCRIPT_TAG"

        # EVENT_HANDLER second
        if re.search(
            r"\bon[a-zA-Z0-9_-]+\s*=",
            output,
            flags=re.IGNORECASE,
        ):
            return "EVENT_HANDLER"

        # DANGEROUS_SCHEME third
        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        # EXTERNAL_EXFIL fourth
        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # MARKDOWN
    # --------------------------------------------------------
    if channel == "markdown":

        # DANGEROUS_SCHEME first
        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        # EXTERNAL_EXFIL second
        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------
    if channel == "url":

        # DANGEROUS_SCHEME first
        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        # EXTERNAL_EXFIL second
        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # SQL
    # --------------------------------------------------------
    if channel == "sql":

        if re.search(
            r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
            output,
            flags=re.IGNORECASE,
        ):
            return "SQL_METACHAR"

        return None

    # --------------------------------------------------------
    # SHELL
    # --------------------------------------------------------
    if channel == "shell":

        if re.search(
            r"""[;&|`<>]|\$\(|\$\{""",
            output,
        ):
            return "SHELL_METACHAR"

        return None

    return None


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # ========================================================
    # 1. INVALID_SCHEMA
    # ========================================================

    try:
        body = await request.json()
    except Exception:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    if not isinstance(body, dict):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    if not isinstance(output, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    # ========================================================
    # 2. ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:
        decoded_violation = channel_violation(channel, decoded)

        if decoded_violation is not None:
            return {
                "safe": False,
                "reason": "ENCODED_PAYLOAD",
            }

    # ========================================================
    # 3. Original output channel rules
    # ========================================================

    violation = channel_violation(channel, output)

    if violation is not None:
        return {
            "safe": False,
            "reason": violation,
        }

    # ========================================================
    # SAFE
    # ========================================================

    return {
        "safe": True,
        "reason": "SAFE",
    }