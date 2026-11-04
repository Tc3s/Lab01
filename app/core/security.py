"""
Security Primitives Engine for E-Commerce Admin & Refund Portal
Location: app/core/security.py

Implements:
1. Robust Password Hashing (Argon2id default via argon2-cffi, bcrypt fallback) with constant-time verification
2. Timing-attack mitigation for missing users (dummy_verify_password)
3. RFC 6238 TOTP Engine (pyotp, 6-digit, 30s step, drift +/-1 step)
4. Anti-Replay Time-Step Tracking (returns exact matched_time_step T = floor(t/30) + delta)
5. Strict Secret Protection (Pydantic SecretStr, exception shielding, zero secret logging)
6. Session Token Generation (256-bit URL-safe) and Session ID Hashing (SHA-256 for audit trails)
"""

import base64
import hashlib
import logging
import secrets
import time
from typing import Optional, Tuple, Union

from argon2 import PasswordHasher, exceptions as argon2_exceptions
import bcrypt
from pydantic import SecretStr
import pyotp

logger = logging.getLogger("app.security")


class SecurityError(Exception):
    """Base exception for all authentication and cryptographic security errors."""
    pass


class InvalidTotpSecretError(SecurityError):
    """
    Raised when a TOTP secret is invalid or malformed.
    Strictly shields raw secret values from appearing in exception messages or stack traces.
    """
    def __init__(self, message: str = "Invalid or malformed TOTP secret."):
        super().__init__(message)


# -----------------------------------------------------------------------------
# Password Hashing & Verification (Argon2id + Bcrypt Fallback)
# -----------------------------------------------------------------------------

# OWASP recommended parameters for Argon2id (RFC 9106)
# memory_cost=65536 (64 MiB), time_cost=3 iterations, parallelism=4 threads
_argon2_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Pre-computed dummy hash to run constant-time verification when a user is not found,
# preventing username enumeration through timing side-channel analysis.
_DUMMY_ARGON2_HASH = _argon2_hasher.hash("dummy_system_password_for_timing_mitigation")


def hash_password(password: str) -> str:
    """
    Hash a plain-text password using Argon2id.

    Args:
        password: The plain-text password to hash.

    Returns:
        Formatted Argon2id string ($argon2id$v=19$m=65536,t=3,p=4$...).

    Raises:
        ValueError: If password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    return _argon2_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a hashed password in constant time.
    Supports both Argon2id ($argon2id$) and bcrypt ($2a$, $2b$, $2y$) hashes.
    Never exposes internal crypto errors to caller.

    Args:
        plain_password: The unhashed user input.
        hashed_password: Stored hash from the database.

    Returns:
        True if the password matches, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False

    try:
        if hashed_password.startswith("$argon2"):
            return _argon2_hasher.verify(hashed_password, plain_password)
        elif hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8")
            )
        else:
            return False
    except (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.VerificationError,
        argon2_exceptions.InvalidHashError
    ):
        return False
    except Exception:
        return False


def dummy_verify_password() -> None:
    """
    Execute constant-time Argon2 verification against a pre-computed dummy hash.
    Used when a requested username does not exist in the database to equalize response times
    and prevent side-channel timing enumeration attacks.
    """
    try:
        _argon2_hasher.verify(_DUMMY_ARGON2_HASH, "invalid_dummy_comparison_mismatch")
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Secret Shielding & Normalization Helpers
# -----------------------------------------------------------------------------

def _extract_and_sanitize_secret(secret: Union[str, SecretStr]) -> str:
    """
    Safely extract raw secret string and normalize Base32 representation.
    Accepts plain string or Pydantic SecretStr.
    Strips internal/external whitespace and converts to uppercase.
    """
    if isinstance(secret, SecretStr):
        raw = secret.get_secret_value()
    elif hasattr(secret, "get_secret_value"):
        raw = secret.get_secret_value()
    else:
        raw = str(secret)

    sanitized = raw.replace(" ", "").strip().upper()
    return sanitized


# -----------------------------------------------------------------------------
# RFC 6238 TOTP Engine with Time Step Tracking
# -----------------------------------------------------------------------------

def generate_totp_secret(length: int = 32) -> str:
    """
    Generate a high-entropy RFC 6238 Base32 secret key.

    Args:
        length: Number of Base32 characters (default: 32 chars = 160 bits entropy).

    Returns:
        RFC 3548 / RFC 4648 Base32-encoded secret string.
    """
    return pyotp.random_base32(length=length)


def generate_totp_uri(
    secret: Union[str, SecretStr],
    account_name: str,
    issuer_name: str = "ECommerceLab01"
) -> str:
    """
    Generate an RFC 6238 Key URI format (otpauth://totp/...) for authenticator enrollment.
    Strictly shields raw secret values from appearing in any exception traces.

    Args:
        secret: Base32 secret key (str or SecretStr).
        account_name: User identifier (e.g. username or email).
        issuer_name: Application name (default: "ECommerceLab01").

    Returns:
        otpauth URI string.

    Raises:
        InvalidTotpSecretError: If the secret is invalid Base32.
    """
    try:
        sanitized = _extract_and_sanitize_secret(secret)
        if not sanitized:
            raise ValueError("Secret cannot be empty.")
        # Validate Base32 decodability without exposing secret in message
        base64.b32decode(sanitized, casefold=True)
        totp = pyotp.TOTP(sanitized)
        return totp.provisioning_uri(name=account_name, issuer_name=issuer_name)
    except Exception:
        raise InvalidTotpSecretError("Failed to generate TOTP URI: invalid secret format.") from None


def get_current_totp_step(for_time: Optional[float] = None, interval: int = 30) -> int:
    """
    Calculate the discrete time step counter T = floor(t / interval) as specified in RFC 6238.

    Args:
        for_time: Unix timestamp in seconds (default: current UTC epoch via time.time()).
        interval: Time step window duration in seconds (default: 30s).

    Returns:
        Integer time step counter.
    """
    t = time.time() if for_time is None else for_time
    return int(t // interval)


def generate_totp_code(
    secret: Union[str, SecretStr],
    time_step: Optional[int] = None,
    for_time: Optional[float] = None,
    interval: int = 30
) -> str:
    """
    Generate a 6-digit TOTP code for a specific time step or timestamp.
    Used for enrollment verification and deterministic automated test harnesses.

    Args:
        secret: Base32 secret key (str or SecretStr).
        time_step: Explicit integer step counter. If None, computed from for_time.
        for_time: Unix timestamp in seconds (default: current UTC time).
        interval: Time step window duration (default: 30s).

    Returns:
        Zero-padded 6-digit OTP string.
    """
    sanitized = _extract_and_sanitize_secret(secret)
    totp = pyotp.TOTP(sanitized, interval=interval)
    if time_step is not None:
        return totp.generate_otp(time_step)
    step = get_current_totp_step(for_time, interval)
    return totp.generate_otp(step)


def verify_totp(
    secret: Union[str, SecretStr],
    otp_code: str,
    valid_window: int = 1,
    for_time: Optional[float] = None,
    interval: int = 30
) -> Tuple[bool, Optional[int]]:
    """
    Verify an RFC 6238 TOTP code against clock drift and return the matched time step.

    This function:
    1. Validates code format (exactly 6 decimal digits).
    2. Tests candidate steps within [-valid_window, +valid_window], checking current step (0) first.
    3. Performs constant-time comparison using secrets.compare_digest.
    4. Identifies the exact matched time step t_match = current_step + delta.
    5. Returns (True, t_match) on success so callers can lock it in Redis via check_and_set_otp_replay.
    6. Returns (False, None) if the code is invalid, expired, or out of window.
    7. Shields all secrets from exceptions and logging.

    Args:
        secret: Base32 secret key (str or SecretStr).
        otp_code: 6-digit OTP code submitted by user.
        valid_window: Number of steps before and after current time to allow (default: 1, drift +/- 1 step).
        for_time: Timestamp to verify at (default: current UTC epoch).
        interval: Time step duration (default: 30s).

    Returns:
        Tuple of (is_valid: bool, matched_time_step: Optional[int]).
    """
    if not otp_code or not secret:
        return False, None

    code_str = str(otp_code).strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False, None

    try:
        sanitized_secret = _extract_and_sanitize_secret(secret)
        totp = pyotp.TOTP(sanitized_secret, interval=interval)
        current_step = get_current_totp_step(for_time, interval)

        # Ordering: check current step (0) first, then adjacent steps (-1, +1, -2, +2, ...)
        offsets = [0]
        for w in range(1, valid_window + 1):
            offsets.extend([-w, w])

        for delta in offsets:
            candidate_step = current_step + delta
            expected_code = totp.generate_otp(candidate_step)
            if secrets.compare_digest(code_str, expected_code):
                return True, candidate_step

        return False, None
    except Exception:
        # Never leak secret or internal trace
        return False, None


# -----------------------------------------------------------------------------
# Session Identifier & Audit Hashing Primitives
# -----------------------------------------------------------------------------

def generate_session_id() -> str:
    """
    Generate a cryptographically secure 256-bit URL-safe session identifier.
    Used for session token generation and post-MFA session rotation.

    Returns:
        43-character URL-safe base64 string.
    """
    return secrets.token_urlsafe(32)


def hash_session_id(session_id: Optional[str]) -> str:
    """
    Hash session ID with SHA-256 for secure audit log recording.
    Prevents session token theft from log files while preserving correlation ability.

    Args:
        session_id: The raw session ID from cookie/header.

    Returns:
        Hex-encoded SHA-256 digest or 'ANONYMOUS' if session_id is None.
    """
    if not session_id:
        return "ANONYMOUS"
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()
