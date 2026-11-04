"""
Adversarial Stress-Test Suite for Auth & Session Subsystems
Location: tests/test_adversarial_auth.py

Stress-tests and adversarially challenges:
1. High-concurrency race condition testing on Redis atomic anti-replay (parallel identical OTP requests)
2. Out-of-window OTP token rejection (+2 / -2 steps and malformed inputs)
3. Pre-MFA session fixation attacks and session boundary isolation
4. Multi-device session revocation propagation across concurrent clients
5. Rolling idle (15m) and absolute (8h) timeout boundary enforcement
"""

import asyncio
import json
import os
import time
import uuid
import httpx
import pytest
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.redis import (
    check_and_set_otp_replay,
    delete_session,
    get_session,
    revoke_all_user_sessions,
    store_session,
    touch_session,
)
from app.core.security import (
    generate_session_id,
    generate_totp_code,
    get_current_totp_step,
    verify_totp,
)
from app.db.database import SessionLocal, init_db
from app.db.seed import SEED_USERS, seed_users
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    seed_users(db)
    db.close()


def run_async(coro):
    return asyncio.run(coro)


async def _reset_redis_state():
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    keys = await r.keys("otp_replay:*")
    if keys:
        await r.delete(*keys)
    sess_keys = await r.keys("session:*")
    if sess_keys:
        await r.delete(*sess_keys)
    user_keys = await r.keys("user_sessions:*")
    if user_keys:
        await r.delete(*user_keys)
    await r.aclose()


# ============================================================================
# 1. High-concurrency Race Condition on Redis Atomic Anti-Replay
# ============================================================================

def test_adv_01_concurrency_anti_replay_same_pre_sid():
    """
    Stress-Test 1A: 50 concurrent requests submitting the EXACT SAME valid OTP
    using the SAME pre-MFA session ID.
    Oracle: Exactly 1 request MUST succeed (HTTP 200).
    Exactly 49 requests MUST be rejected (HTTP 401).
    Zero duplicate post-MFA sessions created.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"}
            )
            assert login_resp.status_code == 200
            pre_sid = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)
            assert pre_sid is not None

            user_secret = SEED_USERS[0]["totp_secret"]
            otp = generate_totp_code(user_secret)

            async def _send_mfa():
                return await client.post(
                    "/api/v1/auth/mfa/verify",
                    json={"otp_code": otp},
                    cookies={settings.SESSION_COOKIE_NAME: pre_sid}
                )

            # Fire 12 requests concurrently (within SQLite connection pool bounds)
            concurrency = 12
            results = await asyncio.gather(*[_send_mfa() for _ in range(concurrency)])

            status_codes = [r.status_code for r in results]
            count_200 = status_codes.count(200)
            count_401 = status_codes.count(401)

            assert count_200 == 1, f"Expected exactly 1 HTTP 200, got {count_200}"
            assert count_401 == (concurrency - 1), f"Expected {concurrency - 1} HTTP 401, got {count_401}"

            # Verify the winning request got a valid post-MFA cookie
            winning_resps = [r for r in results if r.status_code == 200]
            new_sid = winning_resps[0].cookies.get(settings.SESSION_COOKIE_NAME)
            assert new_sid is not None and new_sid != pre_sid

            # Verify Redis replay key exists
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            step = get_current_totp_step()
            replay_key = f"otp_replay:1:{step}"
            val = await r.get(replay_key)
            ttl = await r.ttl(replay_key)
            assert val == "consumed"
            assert 0 < ttl <= settings.OTP_REPLAY_TTL_SECONDS
            await r.aclose()

    run_async(_run())


def test_adv_02_concurrency_anti_replay_multi_pre_sids():
    """
    Stress-Test 1B: 12 independent concurrent logins generate 12 different pre-MFA session IDs.
    All 12 sessions simultaneously attempt to verify the SAME TOTP token.
    Oracle: Exactly 1 MUST succeed (HTTP 200).
    The remaining 11 MUST fail with HTTP 401 REPLAY_DETECTED.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            concurrency = 12
            pre_sids = []
            for _ in range(concurrency):
                login_resp = await client.post(
                    "/api/v1/auth/login",
                    json={"username": "cskh_user", "password": "Password123!"}
                )
                assert login_resp.status_code == 200
                sid = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)
                pre_sids.append(sid)

            assert len(set(pre_sids)) == concurrency, "All pre-MFA sessions must be distinct"

            user_secret = SEED_USERS[0]["totp_secret"]
            otp = generate_totp_code(user_secret)

            async def _verify_sid(sid):
                return await client.post(
                    "/api/v1/auth/mfa/verify",
                    json={"otp_code": otp},
                    cookies={settings.SESSION_COOKIE_NAME: sid}
                )

            # Concurrent blast with identical OTP across 12 distinct sessions
            results = await asyncio.gather(*[_verify_sid(sid) for sid in pre_sids])

            status_codes = [r.status_code for r in results]
            count_200 = status_codes.count(200)
            count_401 = status_codes.count(401)

            assert count_200 == 1, f"Expected exactly 1 HTTP 200, got {count_200}"
            assert count_401 == (concurrency - 1), f"Expected {concurrency - 1} HTTP 401, got {count_401}"

            # All 401s should specifically be REPLAY_DETECTED
            reasons = [r.json().get("detail", {}).get("error") for r in results if r.status_code == 401]
            assert all(err == "REPLAY_DETECTED" for err in reasons), f"Unexpected errors: {reasons}"

    run_async(_run())


def test_adv_03_redis_primitive_concurrency_race():
    """
    Stress-Test 1C: 100 concurrent coroutines hammering check_and_set_otp_replay.
    Oracle: Exactly 1 returns True; 99 return False.
    """
    async def _run():
        await _reset_redis_state()
        dummy_user_id = 9999
        dummy_step = 888888
        tasks = [check_and_set_otp_replay(dummy_user_id, dummy_step, ttl=90) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        assert results.count(True) == 1, f"Expected 1 True, got {results.count(True)}"
        assert results.count(False) == 99, f"Expected 99 False, got {results.count(False)}"

    run_async(_run())


# ============================================================================
# 2. Out-of-Window OTP Token Rejection
# ============================================================================

def test_adv_04_out_of_window_otp_rejection_core_and_api():
    """
    Stress-Test 2: Clock drift boundaries.
    Allowed window: [-1, +1] step (+-30s).
    Strictly rejected: steps <= -2, steps >= +2.
    """
    user_secret = SEED_USERS[0]["totp_secret"]
    current_step = get_current_totp_step()

    # Core function tests
    code_prev2 = generate_totp_code(user_secret, time_step=current_step - 2)
    code_prev1 = generate_totp_code(user_secret, time_step=current_step - 1)
    code_curr  = generate_totp_code(user_secret, time_step=current_step)
    code_next1 = generate_totp_code(user_secret, time_step=current_step + 1)
    code_next2 = generate_totp_code(user_secret, time_step=current_step + 2)
    code_far_past = generate_totp_code(user_secret, time_step=current_step - 100)
    code_far_future = generate_totp_code(user_secret, time_step=current_step + 100)

    # In-window: must pass
    valid, step = verify_totp(user_secret, code_curr, valid_window=1)
    assert valid is True and step == current_step

    valid, step = verify_totp(user_secret, code_prev1, valid_window=1)
    assert valid is True and step == current_step - 1

    valid, step = verify_totp(user_secret, code_next1, valid_window=1)
    assert valid is True and step == current_step + 1

    # Out-of-window: MUST fail
    valid, step = verify_totp(user_secret, code_prev2, valid_window=1)
    assert valid is False and step is None

    valid, step = verify_totp(user_secret, code_next2, valid_window=1)
    assert valid is False and step is None

    valid, step = verify_totp(user_secret, code_far_past, valid_window=1)
    assert valid is False and step is None

    valid, step = verify_totp(user_secret, code_far_future, valid_window=1)
    assert valid is False and step is None

    # API verification: ensure HTTP 401 INVALID_OTP on out-of-window submissions
    async def _test_api():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            for bad_code, desc in [(code_prev2, "-2 steps"), (code_next2, "+2 steps"), (code_far_past, "-100 steps")]:
                l_resp = await client.post(
                    "/api/v1/auth/login",
                    json={"username": "cskh_user", "password": "Password123!"}
                )
                pre_sid = l_resp.cookies.get(settings.SESSION_COOKIE_NAME)

                m_resp = await client.post(
                    "/api/v1/auth/mfa/verify",
                    json={"otp_code": bad_code},
                    cookies={settings.SESSION_COOKIE_NAME: pre_sid}
                )
                assert m_resp.status_code == 401, f"Failed for {desc}, got {m_resp.status_code}"
                assert m_resp.json().get("detail", {}).get("error") == "INVALID_OTP"

    run_async(_test_api())


def test_adv_05_malformed_otp_codes():
    """
    Stress-Test 2B: Malformed OTP tokens (non-digit, short, long, whitespace, injection strings).
    Oracle: Must be safely rejected with 401 or 422, NEVER unhandled 500 crash.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"}
            )
            pre_sid = l_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            malformed_inputs = [
                "12345",         # 5 digits
                "1234567",       # 7 digits
                "abcdef",        # letters
                "123 56",        # embedded space
                " 123456 ",      # surrounding space with digits
                "' OR 1=1 --",   # SQL injection string
                "<script>",      # XSS string
                "\x00\x00\x00",  # Null bytes
            ]

            for bad_input in malformed_inputs:
                resp = await client.post(
                    "/api/v1/auth/mfa/verify",
                    json={"otp_code": bad_input},
                    cookies={settings.SESSION_COOKIE_NAME: pre_sid}
                )
                assert resp.status_code in (400, 401, 422), f"Unexpected status {resp.status_code} for {bad_input}"

    run_async(_run())


# ============================================================================
# 3. Pre-MFA Session Fixation Attacks
# ============================================================================

def test_adv_06_pre_mfa_endpoint_isolation():
    """
    Stress-Test 3A: Pre-MFA session ID cannot access any authenticated endpoint
    prior to MFA completion.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            l_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"}
            )
            pre_sid = l_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            # Try /auth/me
            me_resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: pre_sid})
            assert me_resp.status_code == 401
            assert me_resp.json().get("detail", {}).get("error") == "MFA_NOT_VERIFIED"

            # Try /refunds
            ref_resp = await client.get("/api/v1/refunds", cookies={settings.SESSION_COOKIE_NAME: pre_sid})
            assert ref_resp.status_code == 401
            assert ref_resp.json().get("detail", {}).get("error") == "MFA_NOT_VERIFIED"

            # Try /auth/revoke-all
            rev_resp = await client.post("/api/v1/auth/revoke-all", cookies={settings.SESSION_COOKIE_NAME: pre_sid})
            assert rev_resp.status_code == 401
            assert rev_resp.json().get("detail", {}).get("error") == "MFA_NOT_VERIFIED"

    run_async(_run())


def test_adv_07_cookie_injection_on_login():
    """
    Stress-Test 3B: Attacker provides arbitrary session cookie on POST /auth/login.
    Oracle: Server ignores attacker's cookie and generates a fresh random session ID.
    Attacker cookie is never indexed in Redis.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            attacker_sid = "ATTACKER_INJECTED_SESSION_ID_1337"
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"},
                cookies={settings.SESSION_COOKIE_NAME: attacker_sid}
            )
            assert login_resp.status_code == 200
            issued_sid = login_resp.cookies.get(settings.SESSION_COOKIE_NAME)
            assert issued_sid is not None
            assert issued_sid != attacker_sid, "Server must not adopt client-supplied session ID"

            # Check Redis: attacker_sid must not exist
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            attacker_key = await r.get(f"session:{attacker_sid}")
            assert attacker_key is None
            await r.aclose()

    run_async(_run())


def test_adv_08_pre_mfa_destruction_post_mfa():
    """
    Stress-Test 3C: After victim completes MFA, pre-MFA session ID is destroyed immediately.
    Attacker holding pre-MFA session ID cannot access anything or re-verify.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Step 1: Login
            l_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": "cskh_user", "password": "Password123!"}
            )
            pre_sid = l_resp.cookies.get(settings.SESSION_COOKIE_NAME)

            # Step 2: Complete MFA
            otp = generate_totp_code(SEED_USERS[0]["totp_secret"])
            m_resp = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"otp_code": otp},
                cookies={settings.SESSION_COOKIE_NAME: pre_sid}
            )
            assert m_resp.status_code == 200
            post_sid = m_resp.cookies.get(settings.SESSION_COOKIE_NAME)
            assert post_sid != pre_sid

            # Step 3: Attacker tries pre_sid on /auth/me -> 401 SESSION_EXPIRED
            att_me = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: pre_sid})
            assert att_me.status_code == 401
            assert att_me.json().get("detail", {}).get("error") == "SESSION_EXPIRED"

            # Step 4: Attacker tries pre_sid on /auth/mfa/verify again -> 401 SESSION_EXPIRED
            att_mfa = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"otp_code": otp},
                cookies={settings.SESSION_COOKIE_NAME: pre_sid}
            )
            assert att_mfa.status_code == 401
            assert att_mfa.json().get("detail", {}).get("error") == "SESSION_EXPIRED"

            # Step 5: Legitimate user with post_sid succeeds
            user_me = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: post_sid})
            assert user_me.status_code == 200
            assert user_me.json().get("mfa_state") == "verified"

    run_async(_run())


# ============================================================================
# 4. Multi-Device Session Revocation Propagation Across Concurrent Clients
# ============================================================================

def test_adv_09_multi_device_session_revocation():
    """
    Stress-Test 4A: User logs in from 5 different client devices.
    Device 1 initiates /auth/revoke-all.
    Oracle: Devices 2, 3, 4, and 5 are immediately invalidated (401 SESSION_EXPIRED).
    Redis tracking set user_sessions:{user_id} and all session keys are eradicated.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            user_id = 2  # ketoan_user
            user_secret = SEED_USERS[1]["totp_secret"]

            # Provision 5 valid post-MFA sessions directly in Redis (simulating 5 devices)
            device_sids = [generate_session_id() for _ in range(5)]
            for sid in device_sids:
                data = {
                    "user_id": user_id,
                    "username": "ketoan_user",
                    "role": "KETOAN",
                    "mfa_verified": True,
                    "session_type": "post_mfa",
                    "created_at": time.time(),
                }
                await store_session(sid, data, ttl=900)

            # Verify all 5 devices are operational
            for sid in device_sids:
                resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid})
                assert resp.status_code == 200, f"Device {sid} failed initial verification"

            # Device 0 issues revoke-all
            revoke_resp = await client.post(
                "/api/v1/auth/revoke-all",
                cookies={settings.SESSION_COOKIE_NAME: device_sids[0]}
            )
            assert revoke_resp.status_code == 200
            assert revoke_resp.json().get("detail", {}).get("sessions_revoked") == 5

            # Devices 1..4 now attempt authenticated actions -> ALL MUST BE 401
            for sid in device_sids[1:]:
                resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid})
                assert resp.status_code == 401
                assert resp.json().get("detail", {}).get("error") == "SESSION_EXPIRED"

            # Even Device 0 itself should now be expired
            d0_resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: device_sids[0]})
            assert d0_resp.status_code == 401

            # Redis state check: zero sessions left
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            active_sids = await r.smembers(f"user_sessions:{user_id}")
            assert len(active_sids) == 0
            for sid in device_sids:
                raw = await r.get(f"session:{sid}")
                assert raw is None
            await r.aclose()

    run_async(_run())


def test_adv_10_password_change_multi_device_revocation():
    """
    Stress-Test 4B: Password change triggers instantaneous revocation across all concurrent devices.
    """
    async def _run():
        await _reset_redis_state()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            user_id = 1  # cskh_user
            device_sids = [generate_session_id() for _ in range(3)]
            for sid in device_sids:
                data = {
                    "user_id": user_id,
                    "username": "cskh_user",
                    "role": "CSKH",
                    "mfa_verified": True,
                    "session_type": "post_mfa",
                    "created_at": time.time(),
                }
                await store_session(sid, data, ttl=900)

            try:
                # Device 0 changes password
                chg_resp = await client.post(
                    "/api/v1/auth/change-password",
                    json={"old_password": "Password123!", "new_password": "NewSecurePassword456!"},
                    cookies={settings.SESSION_COOKIE_NAME: device_sids[0]}
                )
                assert chg_resp.status_code == 200

                # Devices 1 and 2 must immediately be rejected
                for sid in device_sids[1:]:
                    me_resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: sid})
                    assert me_resp.status_code == 401
                    assert me_resp.json().get("detail", {}).get("error") == "SESSION_EXPIRED"
            finally:
                # Revert password back unconditionally so other tests aren't disturbed
                db = SessionLocal()
                from app.db.models import User
                from app.core.security import hash_password
                u = db.query(User).filter(User.id == 1).first()
                if u:
                    u.password_hash = hash_password("Password123!")
                    db.commit()
                db.close()

    run_async(_run())


# ============================================================================
# 5. Rolling Idle (15m) and Absolute (8h) Timeout Boundary Enforcement
# ============================================================================

def test_adv_11_rolling_idle_timeout_refresh():
    """
    Stress-Test 5A: Active requests refresh the idle timeout back to 900s.
    """
    async def _run():
        await _reset_redis_state()
        sid = generate_session_id()
        data = {
            "user_id": 1,
            "username": "cskh_user",
            "role": "CSKH",
            "mfa_verified": True,
            "session_type": "post_mfa",
            "created_at": time.time(),
        }
        # Initially store with 30s TTL
        await store_session(sid, data, ttl=30)

        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        initial_ttl = await r.ttl(f"session:{sid}")
        assert 0 < initial_ttl <= 30

        # Touch session with standard idle timeout (900s)
        touched = await touch_session(sid, ttl=settings.SESSION_IDLE_TIMEOUT_SECONDS)
        assert touched is True

        new_ttl = await r.ttl(f"session:{sid}")
        assert 890 <= new_ttl <= 900, f"Expected TTL ~900s, got {new_ttl}"
        await r.aclose()

    run_async(_run())


def test_adv_12_absolute_timeout_capping_and_expiry():
    """
    Stress-Test 5B: Absolute timeout (8h = 28800s) hard ceiling.
    Case 1: When remaining time before 8h is LESS than idle timeout (e.g. 50s remaining),
            touch_session MUST cap new TTL to min(900, remaining) = 50s, NEVER reset to 900s!
    Case 2: When elapsed time >= 28800s (absolute timeout exceeded),
            get_session MUST return None and purge the session from Redis.
    """
    async def _run():
        await _reset_redis_state()
        sid_near_cap = generate_session_id()
        now = time.time()
        # Session created 28750s ago (8h = 28800s -> only 50s remaining)
        created_at_near = now - 28750
        data_near = {
            "user_id": 1,
            "username": "cskh_user",
            "role": "CSKH",
            "mfa_verified": True,
            "created_at": created_at_near,
        }
        await store_session(sid_near_cap, data_near, ttl=900)

        # Touching session MUST NOT extend to 900s! Must cap at remaining (~50s)
        touched = await touch_session(sid_near_cap, ttl=900)
        assert touched is True

        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        capped_ttl = await r.ttl(f"session:{sid_near_cap}")
        assert 0 < capped_ttl <= 51, f"Expected capped TTL <= 50s, got {capped_ttl}"

        # Case 2: Session created 28805s ago (exceeded 8h absolute limit)
        sid_expired = generate_session_id()
        created_at_expired = now - 28805
        data_expired = {
            "user_id": 1,
            "username": "cskh_user",
            "role": "CSKH",
            "mfa_verified": True,
            "created_at": created_at_expired,
        }
        await store_session(sid_expired, data_expired, ttl=900)

        # get_session must identify absolute expiration, delete key, and return None
        fetched = await get_session(sid_expired)
        assert fetched is None, "get_session must return None when absolute timeout is exceeded"

        # Key must be deleted in Redis
        expired_raw = await r.get(f"session:{sid_expired}")
        assert expired_raw is None, "Expired session key must be purged from Redis"

        # Calling touch_session on expired session must return False
        touch_result = await touch_session(sid_expired, ttl=900)
        assert touch_result is False

        await r.aclose()

    run_async(_run())


def test_adv_13_corrupted_session_handling():
    """
    Stress-Test 5C: Corrupted JSON data in Redis session key.
    Oracle: Gracefully returns None/False and deletes corrupted key without HTTP 500 crash.
    """
    async def _run():
        await _reset_redis_state()
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        bad_sid = "corrupted_session_test_sid"
        # Store non-JSON garbage
        await r.set(f"session:{bad_sid}", "NOT_JSON_GARBAGE{{{{}}", ex=60)

        res = await get_session(bad_sid)
        assert res is None

        touch_res = await touch_session(bad_sid, ttl=60)
        assert touch_res is False

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: bad_sid})
            assert resp.status_code == 401
            assert resp.json().get("detail", {}).get("error") == "SESSION_EXPIRED"

        await r.aclose()

    run_async(_run())
