"""
Standardized 9-Field Audit Logging Engine with Recursive Sensitive Data Masking
Location: app/core/audit.py

Mandatory Schema:
- timestamp: ISO 8601 UTC string (e.g. 2026-11-04T12:00:00.123456Z)
- actor_id: User ID (int/str) or None for unauthenticated
- role: Role of actor (e.g. CSKH, KETOAN, ADMIN, ANONYMOUS)
- action: System action name (e.g. LOGIN_SUCCESS, REFUND_CREATE, RBAC_ACCESS_DENIED)
- object_id: Target entity identifier (e.g. refund ID, user ID, None)
- result: Outcome code (SUCCESS, FAILED, DENIED, REPLAY_DETECTED)
- source_ip: Client IP address
- correlation_id: Request tracing ID (UUIDv4)
- session_id_hash: SHA-256 of session ID, or ANONYMOUS / PRE_MFA
- details: Optional sanitized contextual metadata
- PCI-DSS & Data Masking: PAN masked to ************last4, CVV stripped completely.
- Remediation: Integer PAN support, lookarounds, flexible delimiters, JSON unpack recursion, alias expansion.
- Agent: M1 Fix Explorer 1
- Date: 2026-11-04
- Version: 1.1.0-remediated
- Status: Production Ready
"""

import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel

from app.core.config import settings

# Robust regex matching 13-19 digit card numbers with lookarounds and flexible delimiters (space, dot, slash, dash)
PAN_REGEX = re.compile(r"(?<!\d)(?:\d[ ./-]?){12,18}\d(?!\d)")

# Regex matching CVV in text or serialized JSON (handles quotes, colon, equal, dash, 'is', or space)
CVV_STRING_REGEX = re.compile(
    r'(?i)(?:["\']?\b(?:cvv2?|cvc2?|cvn\d?|cid|security_code|card_security_code|cvv_code)\b["\']?\s*(?:[:=]|\bis\b|-|\s)\s*["\']?\d{3,4}["\']?)'
)

# Set of CVV key identifiers to strip completely
CVV_KEYS = {
    "cvv", "cvc", "security_code", "cvv2", "cvc2",
    "card_verification_value", "card_verification_code",
    "cid", "card_security_code", "cvv_code", "cvn", "card_cvv", "card_cvc"
}

# Regex for CVV key matching
CVV_KEY_REGEX = re.compile(
    r'(?i)(?:^|[\W_])(?:cvv\d?|cvc\d?|cvn\d?|cid|security_code|card_security_code|cvv_code|card_cvv|card_cvc)(?:$|[\W_])'
)

# Set of credential and token keys to redact
REDACT_KEYS = {
    "password", "password_hash", "totp_secret", "secret",
    "token", "access_token", "refresh_token", "authorization",
    "raw_token", "cookie", "session_id", "new_password", "old_password",
    "api_secret", "user_password", "current_password", "client_secret"
}

REDACT_SUBSTRINGS = ("password", "secret", "token", "cookie", "authorization")

# Set of PAN key identifiers
PAN_KEYS = {"pan", "card_number", "credit_card", "pan_raw", "account_number"}


def is_cvv_key(k_lower: str) -> bool:
    """Detects whether a dictionary key represents a card security code (CVV/CVC/CID)."""
    if k_lower in CVV_KEYS:
        return True
    return bool(CVV_KEY_REGEX.search(k_lower))


def is_redact_key(k_lower: str) -> bool:
    """Detects whether a dictionary key represents credentials, tokens, or secrets."""
    if k_lower in REDACT_KEYS:
        return True
    return any(sub in k_lower for sub in REDACT_SUBSTRINGS)


def is_pan_key(k_lower: str) -> bool:
    """Detects whether a dictionary key represents a primary account number (PAN)."""
    if k_lower in PAN_KEYS:
        return True
    return (
        "card_number" in k_lower or
        "credit_card" in k_lower or
        k_lower == "pan" or
        k_lower.endswith("_pan") or
        k_lower.startswith("pan_")
    )


def mask_pan_in_str(text: str) -> str:
    """Masks 13-19 digit card numbers to ************last4 and strips string CVV patterns."""
    if not isinstance(text, str):
        text = str(text)

    # Attempt recursive JSON parsing if the string is serialized JSON
    s_stripped = text.strip()
    if (s_stripped.startswith("{") and s_stripped.endswith("}")) or (s_stripped.startswith("[") and s_stripped.endswith("]")):
        try:
            parsed = json.loads(s_stripped)
            sanitized_obj = sanitize_payload(parsed)
            return json.dumps(sanitized_obj, ensure_ascii=False)
        except Exception:
            pass

    def repl(m):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19:
            return f"************{digits[-4:]}"
        return raw

    text = CVV_STRING_REGEX.sub("[CVV_STRIPPED]", text)
    return PAN_REGEX.sub(repl, text)


def sanitize_payload(data: Any) -> Any:
    """
    Recursively sanitizes dictionary, list, set, or string payloads:
    - Completely deletes/strips CVV keys and aliases.
    - Redacts passwords, secrets, tokens, and credentials to [REDACTED].
    - Masks PAN numbers (string, int, float) to ************last4.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower().strip()

            # 1. Eliminate CVV entirely
            if is_cvv_key(k_lower):
                continue

            # 2. Redact credentials
            if is_redact_key(k_lower):
                sanitized[k] = "[REDACTED]"
                continue

            # 3. Mask PAN field
            if is_pan_key(k_lower):
                if isinstance(v, (dict, list, tuple, set, frozenset)):
                    sanitized[k] = sanitize_payload(v)
                else:
                    v_str = str(v)
                    digits = re.sub(r"\D", "", v_str)
                    if 13 <= len(digits) <= 19:
                        sanitized[k] = f"************{digits[-4:]}"
                    else:
                        sanitized[k] = mask_pan_in_str(v_str)
                continue

            # 4. Recurse for nested fields
            sanitized[k] = sanitize_payload(v)
        return sanitized

    elif isinstance(data, (list, tuple, set, frozenset)):
        return [sanitize_payload(item) for item in data]

    elif isinstance(data, (int, float)):
        # Standalone numeric value - check if it is a 13-19 digit card number
        digits = re.sub(r"\D", "", str(data))
        if 13 <= len(digits) <= 19:
            return f"************{digits[-4:]}"
        return data

    elif isinstance(data, str):
        return mask_pan_in_str(data)

    return data


def compute_session_id_hash(session_id: Optional[str], session_type: Optional[str] = None) -> str:
    """Computes SHA-256 of session ID, returning ANONYMOUS or PRE_MFA if absent/pre-auth."""
    if not session_id or session_id == "ANONYMOUS":
        return "ANONYMOUS"
    if session_id == "PRE_MFA" or session_type == "PRE_MFA" or session_id.startswith("pre_mfa"):
        return "PRE_MFA"
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


class AuditRecord(BaseModel):
    timestamp: str
    actor_id: Optional[Union[int, str]] = None
    role: Optional[str] = "ANONYMOUS"
    action: str
    object_id: Optional[str] = None
    result: str
    source_ip: str
    correlation_id: str
    session_id_hash: str
    details: Optional[dict[str, Any]] = None


class AuditLogger:
    def __init__(self, log_file_path: Optional[str] = None):
        self.log_file_path = log_file_path or getattr(settings, "AUDIT_LOG_FILE", "logs/audit.log")
        self._lock = threading.Lock()
        log_dir = os.path.dirname(self.log_file_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def log(
        self,
        actor_id: Optional[Union[int, str]],
        role: Optional[str],
        action: str,
        object_id: Optional[str],
        result: str,
        source_ip: str,
        correlation_id: str,
        session_id: Optional[str] = None,
        session_type: Optional[str] = None,
        details: Optional[dict] = None
    ) -> dict:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        session_id_hash = compute_session_id_hash(session_id, session_type)

        entry = {
            "timestamp": timestamp,
            "actor_id": actor_id,
            "role": role or "ANONYMOUS",
            "action": action,
            "object_id": object_id,
            "result": result,
            "source_ip": source_ip,
            "correlation_id": correlation_id,
            "session_id_hash": session_id_hash
        }

        if details is not None:
            entry["details"] = sanitize_payload(details)

        json_line = json.dumps(entry, ensure_ascii=False, default=str)

        try:
            # 1. Output to stdout
            sys.stdout.write(json_line + "\n")
            sys.stdout.flush()

            # 2. Append to log file (thread-safe)
            with self._lock:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(json_line + "\n")
        except Exception as e:
            sys.stderr.write(f"[AUDIT_LOG_ERROR] Failed to write audit event: {e}\n")

        return entry


# Default global instance
audit_logger = AuditLogger()


def log_audit(
    actor_id: Optional[Union[int, str]],
    role: Optional[str],
    action: str,
    object_id: Optional[str],
    result: str,
    source_ip: str,
    correlation_id: str,
    session_id: Optional[str] = None,
    session_type: Optional[str] = None,
    details: Optional[dict] = None
) -> dict:
    """Public helper function for audit logging."""
    return audit_logger.log(
        actor_id=actor_id,
        role=role,
        action=action,
        object_id=object_id,
        result=result,
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session_id,
        session_type=session_type,
        details=details
    )


# =============================================================================
# Validation Error Sanitization & JSON Serialization Helpers
# =============================================================================

def _sanitize_serializable_value(val: Any) -> Any:
    """Ensures any arbitrary value (including exceptions) is JSON serializable and masked."""
    if isinstance(val, BaseException):
        return mask_pan_in_str(str(val))
    if isinstance(val, (int, float, bool, type(None))):
        return val
    if isinstance(val, (str, bytes)):
        return mask_pan_in_str(str(val))
    if isinstance(val, (list, tuple, set, frozenset)):
        return [_sanitize_serializable_value(item) for item in val]
    if isinstance(val, dict):
        return {str(k): _sanitize_serializable_value(v) for k, v in val.items()}
    # Fallback to string representation if not natively JSON serializable
    try:
        json.dumps(val)
        return val
    except (TypeError, OverflowError):
        return mask_pan_in_str(str(val))


def sanitize_validation_errors(errors: Union[List[Dict[str, Any]], Any]) -> List[Dict[str, Any]]:
    """
    Sanitizes Pydantic validation errors (HTTP 422):
    1. Inspects `loc` hierarchy:
       - If any element in `loc` indicates CVV -> input is replaced with "[REDACTED]".
       - If any element indicates credentials/secrets/tokens/otp -> input is replaced with "[REDACTED]".
       - If any element indicates PAN -> input is masked to ************last4 or [INVALID_PAN].
    2. Ensures all objects in `ctx` (e.g. ValueError in ctx["error"]) and error dicts
       are fully JSON serializable, preventing Starlette JSONResponse 500 TypeError crashes.
    3. Defense-in-depth: runs mask_pan_in_str on msg and non-sensitive inputs.
    """
    if not isinstance(errors, (list, tuple)):
        return sanitize_payload(errors)

    sanitized_list = []
    for raw_err in errors:
        if not isinstance(raw_err, dict):
            sanitized_list.append(_sanitize_serializable_value(raw_err))
            continue

        err = dict(raw_err)

        # 1. Normalize and inspect loc hierarchy
        loc = list(err.get("loc", ()))
        err["loc"] = loc
        loc_str_parts = [str(part).lower().strip() for part in loc]

        is_cvv = any(is_cvv_key(p) for p in loc_str_parts)
        is_pan = any(is_pan_key(p) for p in loc_str_parts)
        is_redact = any(is_redact_key(p) or "otp" in p for p in loc_str_parts)

        # 2. Sanitize input field if present
        if "input" in err:
            inp = err["input"]
            if is_cvv or is_redact:
                err["input"] = "[REDACTED]"
            elif is_pan:
                if inp is None:
                    err["input"] = "[REDACTED]"
                else:
                    digits = re.sub(r"\D", "", str(inp))
                    if len(digits) >= 4:
                        err["input"] = f"************{digits[-4:]}"
                    else:
                        err["input"] = "[INVALID_PAN]"
            else:
                # Non-sensitive field: sanitize any accidental card numbers/CVVs in payload
                err["input"] = _sanitize_serializable_value(sanitize_payload(inp))

        # 3. Sanitize msg
        if "msg" in err and isinstance(err["msg"], str):
            err["msg"] = mask_pan_in_str(err["msg"])

        # 4. Sanitize ctx
        if "ctx" in err:
            ctx = err["ctx"]
            if isinstance(ctx, dict):
                clean_ctx = {}
                for ck, cv in ctx.items():
                    ck_lower = str(ck).lower().strip()
                    if is_cvv_key(ck_lower) or is_redact_key(ck_lower):
                        clean_ctx[ck] = "[REDACTED]"
                    elif is_pan_key(ck_lower):
                        digits = re.sub(r"\D", "", str(cv))
                        clean_ctx[ck] = f"************{digits[-4:]}" if len(digits) >= 4 else "[INVALID_PAN]"
                    else:
                        clean_ctx[ck] = _sanitize_serializable_value(cv)
                err["ctx"] = clean_ctx
            else:
                err["ctx"] = _sanitize_serializable_value(ctx)

        sanitized_list.append(err)

    return sanitized_list
