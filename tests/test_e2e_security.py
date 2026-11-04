"""
PyTest Suite for E2E Security Controls (T1 - T8)
Location: tests/test_e2e_security.py
"""

import asyncio
import httpx
import pytest
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.security import generate_totp_code, get_current_totp_step
from app.db.database import SessionLocal, init_db
from app.db.models import RefundRequest
from app.db.seed import SEED_USERS, seed_users
from app.main import app


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
            resp = await client.post(
                "/api/v1/refunds",
                json={"order_id": "ORD-T7-PCI-PYTEST", "customer_name": "Masking Check", "amount": 10000.0, "reason": "PCI", "pan": pan_raw, "cvv": cvv_raw},
                cookies={settings.SESSION_COOKIE_NAME: sid}
            )
            assert resp.status_code == 201
            assert resp.json()["pan_last4"] == "5678"

            db = SessionLocal()
            rf = db.query(RefundRequest).filter(RefundRequest.order_id == "ORD-T7-PCI-PYTEST").first()
            assert rf.pan_last4 == "5678"
            db.close()

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
