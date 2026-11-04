# Project: E-Commerce Security Lab 01 (Secure Admin & Refund Portal)

## Architecture
The system is built as a hardened e-commerce administrative service implementing defense-in-depth and segregation of duties for Customer Service (CSKH), Accounting (Kế toán), and Administration (Admin).

- **Backend Framework**: Python FastAPI (v0.142+) with Uvicorn.
- **Session & In-Memory Security Engine**: Redis 7. Handles atomic anti-replay locks (`SET NX EX`), session storage with rolling idle timeout (15m) and absolute timeout (8h), and user session tracking sets (`user_sessions:{user_id}`) for instant bulk revocation.
- **Database Layer**: SQLAlchemy ORM with SQLite (persistent file `./data/ecommerce.db`) with full PostgreSQL compatibility.
- **Security Primitives**:
  - RFC 6238 TOTP engine (`pyotp`) with 30s step, 6 digits, and $\pm 1$ step clock drift window.
  - Password hashing using Argon2/bcrypt.
  - Session fixation defense: pre-MFA temporary session rotation into cryptographically secure post-MFA session ID (`secrets.token_urlsafe(32)`), with immediate destruction of pre-MFA session.
  - Role-based Access Control (RBAC) & Segregation of Duties (SoD) enforced strictly at controller/dependency injection level.
  - Audit logging middleware capturing 9 mandatory fields (`timestamp`, `actor_id`, `role`, `action`, `object_id`, `result`, `source_ip`, `correlation_id`, `session_id_hash`), with automated PAN masking (last-4 only) and complete elimination of CVV, passwords, and raw tokens.
- **Deployment**: Docker & Docker Compose (`docker compose up --build`).

## Feature Inventory
Every requirement from ORIGINAL_REQUEST.md and lab slides is cataloged below with its assigned milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | TOTP RFC 6238 Engine | 6-digit, 30s step, ±1 step clock drift verification; secret never logged | M1 | ORIGINAL_REQUEST §R1.1, Slide 97 |
| 2 | Redis Anti-Replay Guard | Atomic `SET NX` with 90s TTL to prevent duplicate OTP consumption in same window | M1 | ORIGINAL_REQUEST §R1.2, Slide 97 |
| 3 | Audit Logging Engine | Standardized JSON audit schema with 9 mandatory fields & correlation ID propagation | M1 | ORIGINAL_REQUEST §R1.5, Slide 97 |
| 4 | Sensitive Data Masker | Masks PAN to `************last4`; completely discards CVV; redacts secrets | M1 | ORIGINAL_REQUEST §R1.5, Slide 97 |
| 5 | Relational Database & Seed Data | Models for User, Role (CSKH, KETOAN, ADMIN), and RefundRequest | M1 | ORIGINAL_REQUEST §R1.4, Slide 97 |
| 6 | Auth & MFA Endpoints | `/login`, `/mfa/verify`, `/logout`, `/revoke-all`, `/change-password`, `/auth/me` | M2 | ORIGINAL_REQUEST §R1.1, R1.3, Slide 97 |
| 7 | Session Hardening & Rotation | HttpOnly/Secure/SameSite cookies, pre-MFA to post-MFA rotation, 15m idle / 8h absolute timeout | M2 | ORIGINAL_REQUEST §R1.3, Slide 97 |
| 8 | RBAC & SoD API Enforcement | Backend authorization guards: CSKH creates refund, Kế toán approves, 403 on bypass | M2 | ORIGINAL_REQUEST §R1.4, Slide 97 |
| 9 | Refund Management APIs | `POST /refunds`, `GET /refunds`, `POST /refunds/{id}/approve`, `POST /refunds/{id}/reject` | M2 | ORIGINAL_REQUEST §R1.4, Slide 97 |
| 10 | Session Revocation Lifecycle | Invalidation on logout, password change, MFA reset, and user-wide revocation | M2 | ORIGINAL_REQUEST §R1.6, Slide 97 |
| 11 | Admin Portal APIs | Admin view for audit logs, active sessions, and emergency user session revocation | M2 | ORIGINAL_REQUEST §R1.6, Slide 97 |
| 12 | Automated E2E Test Suite (T1-T8) | PyTest & standalone script executing all 8 security test cases deterministically | M3 | ORIGINAL_REQUEST §R3, Slide 98 |
| 13 | Primary Evidence Collector | Captures HTTP I/O, Redis state, TTL, and matching audit lines into `evidence/T*.json` | M3 | ORIGINAL_REQUEST §R3, Slide 98 |
| 14 | Docker Compose Packaging | Dockerfile and docker-compose.yml orchestrating web app and Redis container | M4 | ORIGINAL_REQUEST §R2 |
| 15 | Deployment Documentation & README | Comprehensive README with setup, architecture, and verification instructions | M4 | ORIGINAL_REQUEST §R2, R3 |
| 16 | Final Verification & Forensic Audit | Containerized execution of T1-T8, adversarial edge testing, and forensic audit | M5 | Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Security & State Infrastructure | Redis connection pool & atomic primitives, TOTP RFC 6238 engine, Audit logging engine with 9 fields & data masking, DB models & seed accounts | None | DONE |
| M2 | Business Logic & API Endpoints | Authentication routes, post-MFA session rotation, RBAC/SoD dependency guards, refund workflow endpoints, session revocation handlers | M1 | DONE |
| M3 | Automated E2E Test Suite & Evidence | Test runner for T1 through T8, evidence capture (`evidence/T*.json`), `evidence/SUMMARY.md` | M2 | DONE |
| M4 | Containerization & Documentation | `Dockerfile`, `docker-compose.yml`, `.env.example`, comprehensive `README.md` | M2, M3 | IN_PROGRESS |
| M5 | Final Verification & Forensic Audit | End-to-end container test pass, adversarial validation, forensic auditor verification | M1, M2, M3, M4 | PLANNED |

## Interface Contracts

### M1 (Core Security) ↔ M2 (API & Controllers)
- **Redis Helpers (`app.core.redis`)**:
  - `async def store_session(session_id: str, data: dict, ttl: int = 900) -> None`
  - `async def get_session(session_id: str) -> Optional[dict]`
  - `async def delete_session(session_id: str, user_id: Optional[int] = None) -> bool`
  - `async def revoke_all_user_sessions(user_id: int) -> int`
  - `async def check_and_set_otp_replay(user_id: int, time_step: int, ttl: int = 90) -> bool`
- **TOTP Engine (`app.core.security`)**:
  - `def verify_totp(secret: str, otp_code: str, valid_window: int = 1) -> tuple[bool, Optional[int]]`
  - Returns `(is_valid, matched_time_step)`.
- **Audit Logger (`app.core.audit`)**:
  - `def log_audit(actor_id: Optional[int], role: Optional[str], action: str, object_id: Optional[str], result: str, source_ip: str, correlation_id: str, session_id: Optional[str], details: Optional[dict] = None) -> None`
  - Masks PAN, strips CVV, hashes session ID with SHA-256, writes JSON to `logs/audit.log` and stdout.

### M2 (API & Controllers) ↔ M3 (E2E Test Runner)
- Base URL: `http://localhost:8000/api/v1`
- Auth Endpoints:
  - `POST /auth/login` -> payload: `{"username": str, "password": str}`, returns 200 with pre-MFA cookie and `{"mfa_required": true}`.
  - `POST /auth/mfa/verify` -> payload: `{"otp_code": str}`, returns 200 with new session cookie, or 401 with `{"detail": {"error": "REPLAY_DETECTED"}}`.
  - `POST /auth/logout` -> returns 200, deletes session.
  - `POST /auth/revoke-all` -> returns 200, revokes all user sessions.
  - `GET /auth/me` -> returns 200 with user profile, or 401.
- Refund Endpoints:
  - `POST /refunds` -> header: `Cookie: session_id=...` (CSKH role only), payload: `{"order_id": str, "amount": float, "reason": str, "pan": str, "cvv": Optional[str]}`, returns 201 with `{"id": str, "status": "PENDING", "pan_last4": str}`.
  - `POST /refunds/{id}/approve` -> header: `Cookie: session_id=...` (Kế toán role only), returns 200 with `{"status": "APPROVED"}`. CSKH calls return 403 Forbidden.

## Code Layout
```
/home/tcus/Desktop/An toan thuong mai dien tu/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── README.md
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── security.py
│   │   ├── redis.py
│   │   └── audit.py
│   ├── db/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   ├── models.py
│   │   └── seed.py
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── correlation.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   └── refund.py
│   └── api/
│       ├── __init__.py
│       ├── deps.py
│       └── v1/
│           ├── __init__.py
│           ├── auth.py
│           ├── refunds.py
│           └── admin.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   └── test_e2e_security.py
├── scripts/
│   ├── run_e2e_tests.py
│   └── seed_db.py
├── logs/
│   └── audit.log
└── evidence/
    ├── T1_totp_valid.json
    ├── T2_replay_detected.json
    ├── T3_otp_invalid_expired.json
    ├── T4_session_fixation.json
    ├── T5_rbac_bypass_denied.json
    ├── T6_refund_flow_valid.json
    ├── T7_log_masking.json
    ├── T8_session_revocation.json
    └── SUMMARY.md
```
