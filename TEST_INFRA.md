# E2E Test Infra: Secure E-Commerce Lab 01

## Test Philosophy
- Opaque-box, requirement-driven verification derived directly from `ORIGINAL_REQUEST.md` and Lab 01 slide specifications.
- Deterministic assertions against live HTTP endpoints, Redis memory state, and SIEM audit log files.
- Zero tolerance for simulated or fake tests: every test captures real HTTP requests/responses, actual Redis key TTLs, and unredacted/redacted audit log lines into JSON evidence artifacts.

## Feature Inventory & Test Mapping
| # | Feature | Source (Requirement) | Target Test ID | Acceptance Condition |
|---|---------|---------------------|:--------------:|----------------------|
| 1 | Valid TOTP Verification | ORIGINAL_REQUEST §R1.1, Slide 97 | T1 | HTTP 200, MFA verified, session created, audit success log |
| 2 | Redis Anti-Replay Guard | ORIGINAL_REQUEST §R1.2, Slide 97 | T2 | Replay rejected (HTTP 401/403), `REPLAY_DETECTED` event, Redis key exists with positive TTL |
| 3 | Invalid / Expired OTP Rejection | ORIGINAL_REQUEST §R1.1, Slide 97 | T3 | HTTP 401/403, no privileged session, audit failure log |
| 4 | Post-MFA Session Fixation Rotation | ORIGINAL_REQUEST §R1.3, Slide 97 | T4 | `SID_before != SID_after`, request with `SID_before` rejected (401/403), new SID works |
| 5 | RBAC & Segregation of Duties Bypass | ORIGINAL_REQUEST §R1.4, Slide 97 | T5 | CSKH calling approve receives HTTP 403, audit `result=DENIED`, status remains `PENDING` |
| 6 | Valid Segregation of Duties Refund Flow | ORIGINAL_REQUEST §R1.4, Slide 97 | T6 | CSKH creates (201/200), Kế toán approves (200), status `APPROVED`, 2 distinct audit events |
| 7 | Sensitive Data Masking Verification | ORIGINAL_REQUEST §R1.5, Slide 97 | T7 | CVV completely absent from logs/DB; full PAN absent; PAN displays strictly as `************last4` |
| 8 | Session Revocation Lifecycle | ORIGINAL_REQUEST §R1.6, Slide 97 | T8 | Session invalidated on logout/reset; subsequent request receives HTTP 401/403; Redis key removed |

## Test Architecture
- **Test Runner Location**: `scripts/run_e2e_tests.py` and `tests/test_e2e_security.py`
- **Execution Mechanism**:
  - Direct HTTP client (`httpx.Client`) with cookie jar support.
  - Redis verification client (`redis.Redis`) inspecting raw keys (`otp_replay:*`, `session:*`, `user_sessions:*`).
  - Audit log file parser scanning `logs/audit.log` for exact correlation IDs and regex verification.
- **Evidence Output Format**:
  - Individual test case results saved to `evidence/T{1..8}_*.json`.
  - Comprehensive markdown report saved to `evidence/SUMMARY.md`.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Expected Outcome |
|---|----------|--------------------|------------------|
| 1 | CSKH user onboarding -> Login -> MFA -> Create Refund | F1, F6, F7, F8, F9 | User fully authenticated, refund pending approval, PAN masked |
| 2 | Malicious Insider Attempting Refund Approval | F8, F9, F11 | CSKH receives 403 Forbidden, security team alert logged |
| 3 | OTP Interception & Rapid Replay Attack | F1, F2, F3 | First login succeeds; second concurrent attempt fails with 401 REPLAY_DETECTED |
| 4 | Post-Authentication Session Fixation Hijack Attempt | F6, F7, F10 | Attacker possessing pre-auth SID is locked out upon victim MFA completion |
| 5 | Compromised Credential Emergency Revocation | F10, F11 | Admin revokes all user sessions; all concurrent client devices immediately receive 401 |

## Coverage Thresholds
- **Mandatory**: 100% pass rate across T1 through T8.
- **Evidence**: 8 JSON evidence files created in `evidence/` with valid schema and verified raw outputs.
- **Integrity**: Zero simulated responses; direct socket/HTTP verification.
