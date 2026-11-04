"""
PyTest Suite for E2E Security Controls (T1 - T8)
Location: tests/test_e2e_security.py
"""

import asyncio
import json
import os
import time
import uuid
from typing import Optional
import httpx
import pytest
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.security import generate_totp_code, get_current_totp_step
from app.db.database import SessionLocal, init_db
from app.db.models import RefundRequest
from app.db.seed import SEED_USERS, seed_users
from app.main import app


def _find_audit_entry(correlation_id: str, action: Optional[str] = None) -> Optional[dict]:
    """Helper to inspect logs/audit.log deterministically by correlation_id."""
    if not os.path.exists(settings.AUDIT_LOG_FILE):
        return None
    with open(settings.AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        for line in reversed(f.readlines()):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("correlation_id") == correlation_id:
                    if action is None or record.get("action") == action:
                        return record
            except Exception:
                pass
    return None


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()
    db = SessionLocal()
    seed_users(db)
    db.close()


def run_async(coro):
    return asyncio.run(coro)


async def _clean_replay_keys():
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    keys = await r.keys("otp_replay:*")
    if keys:
        await r.delete(*keys)
    await r.aclose()


def test_t1_totp_valid():
    """T1: Login with password -> verify correct TOTP -> HTTP 200, MFA state=verified."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"}
            )
            assert login_resp.status_code == 200
            pre_sid = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)
            assert pre_sid is not None

            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            mfa_resp = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"otp_code": otp},
                cookies={settings.SESSION_COOKIE_NAME: pre_sid}
            )
            assert mfa_resp.status_code == 200
            assert mfa_resp.json().get("mfa_state") == "verified"
            assert mfa_resp.cookies.get(settings.SESSION_COOKIE_NAME) is not None

    run_async(_test())


def test_t2_replay_otp():
    """T2: Replay same OTP in same time-step -> HTTP 401/403, REPLAY_DETECTED."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # First use
            l1 = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            sid1 = l1.cookies.get(settings.SESSION_COOKIE_NAME)
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m1 = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies={settings.SESSION_COOKIE_NAME: sid1})
            assert m1.status_code == 200

            # Second attempt with same OTP
            l2 = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            sid2 = l2.cookies.get(settings.SESSION_COOKIE_NAME)
            m2 = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies={settings.SESSION_COOKIE_NAME: sid2})
            assert m2.status_code in (401, 403)
            assert m2.json().get("detail", {}).get("error") == "REPLAY_DETECTED"

    run_async(_test())


def test_t3_otp_invalid():
    """T3: Submit wrong OTP -> HTTP 401, no privileged session."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            login_resp = await client.post("/api/v1/auth/login", json={"username": "ketoan_user", "password": "Password123!"})
            sid = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            mfa_resp = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"otp_code": "000000"},
                cookies={settings.SESSION_COOKIE_NAME: sid}
            )
            assert mfa_resp.status_code == 401

    run_async(_test())


def test_t4_session_fixation():
    """T4: SID_before != SID_after, old SID revoked."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            login_resp = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            sid_before = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            mfa_resp = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"otp_code": otp},
                cookies={settings.SESSION_COOKIE_NAME: sid_before}
            )
            assert mfa_resp.status_code == 200
            sid_after = mfa_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            assert sid_before != sid_after
            old_call = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid_before})
            assert old_call.status_code == 401
            new_call = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid_after})
            assert new_call.status_code == 200

    run_async(_test())


def test_t5_rbac_bypass():
    """T5: CSKH calling approve API returns 403 Forbidden."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            sid_pre = l.cookies.get(settings.SESSION_COOKIE_NAME)
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies={settings.SESSION_COOKIE_NAME: sid_pre})
            assert m.status_code == 200
            cskh_sid = m.cookies.get(settings.SESSION_COOKIE_NAME)

            c_resp = await client.post(
                "/api/v1/refunds",
                json={
                    "order_id": "ORD-T5-PYTEST",
                    "customer_name": "Test Customer",
                    "amount": 100000.0,
                    "reason": "Test",
                    "pan": "4532-1234-5678-9999",
                    "cvv": "123"
                },
                cookies={settings.SESSION_COOKIE_NAME: cskh_sid}
            )
            assert c_resp.status_code == 201
            refund_id = c_resp.json()["id"]

            app_resp = await client.post(
                f"/api/v1/refunds/{refund_id}/approve",
                cookies={settings.SESSION_COOKIE_NAME: cskh_sid}
            )
            assert app_resp.status_code == 403

    run_async(_test())


def test_t6_refund_flow_valid():
    """T6: CSKH creates (201), KETOAN approves (200)."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l_cskh = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp_cskh = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m_cskh = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp_cskh}, cookies=l_cskh.cookies)
            assert m_cskh.status_code == 200
            sid_cskh = m_cskh.cookies.get(settings.SESSION_COOKIE_NAME)

            l_kt = await client.post("/api/v1/auth/login", json={"username": "ketoan_user", "password": "Password123!"})
            otp_kt = generate_totp_code(SEED_USERS[1]["totp_secret"])
            m_kt = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp_kt}, cookies=l_kt.cookies)
            assert m_kt.status_code == 200
            sid_kt = m_kt.cookies.get(settings.SESSION_COOKIE_NAME)

            cr = await client.post(
                "/api/v1/refunds",
                json={"order_id": "ORD-T6-SOD", "customer_name": "Test", "amount": 250000.0, "reason": "Valid SoD", "pan": "4111-2222-3333-4444"},
                cookies={settings.SESSION_COOKIE_NAME: sid_cskh}
            )
            assert cr.status_code == 201
            rf_id = cr.json()["id"]

            ap = await client.post(f"/api/v1/refunds/{rf_id}/approve", cookies={settings.SESSION_COOKIE_NAME: sid_kt})
            assert ap.status_code == 200
            assert ap.json()["status"] == "APPROVED"

    run_async(_test())


def test_t7_log_masking():
    """T7: PAN masked in DB and logs, CVV never saved."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies=l.cookies)
            assert m.status_code == 200
            sid = m.cookies.get(settings.SESSION_COOKIE_NAME)

            pan_raw = "4556-7890-1234-5678"
            cvv_raw = "987"
            corr_id = f"pytest-t7-{int(time.time())}"
            resp = await client.post(
                "/api/v1/refunds",
                json={"order_id": "ORD-T7-PCI-PYTEST", "customer_name": "Masking Check", "amount": 10000.0, "reason": "PCI", "pan": pan_raw, "cvv": cvv_raw},
                cookies={settings.SESSION_COOKIE_NAME: sid},
                headers={"X-Correlation-ID": corr_id}
            )
            assert resp.status_code == 201
            assert resp.json()["pan_last4"] == "5678"

            db = SessionLocal()
            rf = db.query(RefundRequest).filter(RefundRequest.order_id == "ORD-T7-PCI-PYTEST").first()
            assert rf.pan_last4 == "5678"
            db.close()

            # Audit log verification
            audit_record = _find_audit_entry(corr_id, "REFUND_CREATE")
            assert audit_record is not None, "Audit record for T7 missing"
            details = audit_record.get("details", {})
            assert "cvv" not in details, "CVV key present in audit details"
            assert cvv_raw not in json.dumps(details), "CVV value leaked into audit details"
            assert pan_raw not in json.dumps(audit_record), "Raw PAN leaked into audit record"
            assert "************5678" in json.dumps(audit_record), "PAN not properly masked in audit record"

    run_async(_test())


def test_t7_regression_invalid_cvv_sanitized():
    """Regression: Invalid CVV returns HTTP 422 (not 500) and strips CVV from audit log and response."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies=l.cookies)
            sid = m.cookies.get(settings.SESSION_COOKIE_NAME)

            bad_cvv = "12345"
            corr_id = f"pytest-reg-bad-cvv-{int(time.time())}"
            resp = await client.post(
                "/api/v1/refunds",
                json={
                    "order_id": "ORD-REG-CVV",
                    "customer_name": "Regression CVV",
                    "amount": 1000.0,
                    "reason": "Test Bad CVV",
                    "pan": "4111-2222-3333-4444",
                    "cvv": bad_cvv
                },
                cookies={settings.SESSION_COOKIE_NAME: sid},
                headers={"X-Correlation-ID": corr_id}
            )
            # Must return HTTP 422, never crash with HTTP 500
            assert resp.status_code == 422, f"Expected 422, got {resp.status_code}"

            # Response body must be valid JSON and not leak CVV
            body = resp.json()
            assert "detail" in body
            assert bad_cvv not in resp.text, "Bad CVV leaked in response body"

            # Audit log check
            audit_record = _find_audit_entry(corr_id, "VALIDATION_ERROR")
            assert audit_record is not None, "VALIDATION_ERROR audit record not found"
            details = audit_record.get("details", {})
            assert bad_cvv not in json.dumps(details), f"CRITICAL: Invalid CVV {bad_cvv} leaked into audit details"

    run_async(_test())


def test_t7_regression_invalid_pan_sanitized():
    """Regression: Invalid PAN (short & bad chars) returns HTTP 422 (not 500) and masks PAN in audit log."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies=l.cookies)
            sid = m.cookies.get(settings.SESSION_COOKIE_NAME)

            # Case 1: Short PAN (12 digits)
            short_pan = "411122223333"
            corr_id_short = f"pytest-reg-pan-short-{int(time.time())}"
            resp_short = await client.post(
                "/api/v1/refunds",
                json={
                    "order_id": "ORD-REG-PAN-SHORT",
                    "customer_name": "Regression PAN Short",
                    "amount": 1000.0,
                    "reason": "Test Short PAN",
                    "pan": short_pan,
                    "cvv": "123"
                },
                cookies={settings.SESSION_COOKIE_NAME: sid},
                headers={"X-Correlation-ID": corr_id_short}
            )
            assert resp_short.status_code == 422, f"Expected 422, got {resp_short.status_code}"
            assert short_pan not in resp_short.text
            audit_short = _find_audit_entry(corr_id_short, "VALIDATION_ERROR")
            assert audit_short is not None
            assert short_pan not in json.dumps(audit_short.get("details", {})), "Short PAN leaked into audit details"

            # Case 2: Custom validator failure (invalid characters triggering ValueError)
            bad_char_pan = "4111-XXXX-3333-4444"
            corr_id_char = f"pytest-reg-pan-char-{int(time.time())}"
            resp_char = await client.post(
                "/api/v1/refunds",
                json={
                    "order_id": "ORD-REG-PAN-CHAR",
                    "customer_name": "Regression PAN Char",
                    "amount": 1000.0,
                    "reason": "Test Bad Char PAN",
                    "pan": bad_char_pan,
                    "cvv": "123"
                },
                cookies={settings.SESSION_COOKIE_NAME: sid},
                headers={"X-Correlation-ID": corr_id_char}
            )
            assert resp_char.status_code == 422, f"Expected 422, got {resp_char.status_code}"
            assert bad_char_pan not in resp_char.text
            audit_char = _find_audit_entry(corr_id_char, "VALIDATION_ERROR")
            assert audit_char is not None
            assert bad_char_pan not in json.dumps(audit_char.get("details", {})), "Bad char PAN leaked into audit details"

    run_async(_test())


def test_sod_rejection_self_collision():
    """SoD Regression: Creator cannot reject their own refund request (HTTP 403 SOD_VIOLATION)."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Login ketoan_user (id=2)
            l_kt = await client.post("/api/v1/auth/login", json={"username": "ketoan_user", "password": "Password123!"})
            otp_kt = generate_totp_code(SEED_USERS[1]["totp_secret"])
            m_kt = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp_kt}, cookies=l_kt.cookies)
            assert m_kt.status_code == 200
            sid_kt = m_kt.cookies.get(settings.SESSION_COOKIE_NAME)

            # Insert refund created by ketoan_user (id=2)
            rf_id = str(uuid.uuid4())
            db = SessionLocal()
            rf = RefundRequest(
                id=rf_id,
                order_id=f"ORD-SOD-REJ-{int(time.time())}",
                customer_name="Self Rejection Test",
                amount=100000.0,
                reason="SoD Rejection Check",
                pan_last4="1234",
                status="PENDING",
                created_by_id=2
            )
            db.add(rf)
            db.commit()
            db.close()

            # Attempt self-rejection by creator (id=2)
            corr_id_self = f"pytest-sod-rej-self-{int(time.time())}"
            rej_self = await client.post(
                f"/api/v1/refunds/{rf_id}/reject",
                cookies={settings.SESSION_COOKIE_NAME: sid_kt},
                headers={"X-Correlation-ID": corr_id_self}
            )
            assert rej_self.status_code == 403, f"Expected 403, got {rej_self.status_code}"
            assert rej_self.json()["detail"]["error"] == "SOD_VIOLATION"

            audit_self = _find_audit_entry(corr_id_self, "REFUND_REJECT_SELF_COLLUSION")
            assert audit_self is not None
            assert audit_self["result"] == "DENIED"

            # CSKH attempt to reject -> 403 ACCESS_DENIED
            l_cskh = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp_cskh = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m_cskh = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp_cskh}, cookies=l_cskh.cookies)
            sid_cskh = m_cskh.cookies.get(settings.SESSION_COOKIE_NAME)

            rej_cskh = await client.post(
                f"/api/v1/refunds/{rf_id}/reject",
                cookies={settings.SESSION_COOKIE_NAME: sid_cskh}
            )
            assert rej_cskh.status_code == 403

    run_async(_test())


def test_t8_session_revocation():
    """T8: Logout invalidates session immediately (subsequent request returns 401)."""
    async def _test():
        await _clean_replay_keys()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l = await client.post("/api/v1/auth/login", json={"username": "cskh_user", "password": "Password123!"})
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m = await client.post("/api/v1/auth/mfa/verify", json={"otp_code": otp}, cookies=l.cookies)
            assert m.status_code == 200
            sid = m.cookies.get(settings.SESSION_COOKIE_NAME)

            check_pre = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid})
            assert check_pre.status_code == 200

            logout_resp = await client.post("/api/v1/auth/logout", cookies={settings.SESSION_COOKIE_NAME: sid})
            assert logout_resp.status_code == 200

            check_post = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid})
            assert check_post.status_code == 401

    run_async(_test())
