# BÁO CÁO KẾT QUẢ KIỂM CHỨNG BẢO MẬT (TEST SUITE T1 - T8)

- Thời gian thực hiện: 2026-11-04 13:50:46 UTC
- Trạng thái toàn bộ bộ test: **100% PASS (8/8 Test Cases)**

| Test ID | Tên Kiểm Thử | Điều Kiện PASS | Kết Quả Thực Tế | File Bằng Chứng |
|---------|--------------|----------------|-----------------|-----------------|
| **T1** | TOTP Hợp Lệ | HTTP 200, MFA state=verified | PASS (200, Verified) | [`T1_totp_valid.json`](./T1_totp_valid.json) |
| **T2** | Replay OTP | HTTP 401/403, REPLAY_DETECTED | PASS (401, REPLAY_DETECTED, Redis TTL verified) | [`T2_replay_detected.json`](./T2_replay_detected.json) |
| **T3** | OTP Sai / Hết Hạn | HTTP 401, không tạo privileged session | PASS (401, Denied) | [`T3_otp_invalid_expired.json`](./T3_otp_invalid_expired.json) |
| **T4** | Session Fixation | SID_before != SID_after, SID cũ bị hủy (401) | PASS (Rotated, Old SID revoked) | [`T4_session_fixation.json`](./T4_session_fixation.json) |
| **T5** | RBAC Bypass | CSKH approve -> HTTP 403, audit result=DENIED | PASS (403 Forbidden, DENIED) | [`T5_rbac_bypass_denied.json`](./T5_rbac_bypass_denied.json) |
| **T6** | Luồng Hợp Lệ (SoD) | CSKH tạo (201), Kế toán duyệt (200) | PASS (2 requests + 2 audit events) | [`T6_refund_flow_valid.json`](./T6_refund_flow_valid.json) |
| **T7** | Log Masking | CVV không tồn tại, PAN mask `************last4` | PASS (Zero leak, last-4 only) | [`T7_log_masking.json`](./T7_log_masking.json) |
| **T8** | Session Revocation | Request sau logout nhận HTTP 401 | PASS (401, Redis session deleted) | [`T8_session_revocation.json`](./T8_session_revocation.json) |

## Chi Tiết Kiểm Tra Các Kiểm Soát

1. **RFC 6238 TOTP Engine**: Tính toán chính xác theo chuẩn RFC 6238 với time step 30s, hỗ trợ clock drift ±1 step, không ghi secret vào bất kỳ log nào.
2. **Anti-Replay bằng Redis**: Lệnh atomic `SET otp_replay:{user_id}:{time_step} 'consumed' EX 90 NX` bảo vệ tuyệt đối trước tấn công phát lại trong cùng cửa sổ time-step.
3. **Session Hardening**: Cookie HttpOnly, SameSite, Secure. Thu hồi pre-MFA session và cấp mới post-MFA 256-bit URL-safe token. Cơ chế idle timeout (15 phút) và absolute timeout (8 giờ).
4. **RBAC & Segregation of Duties (SoD)**: Tách biệt nghiêm ngặt quyền hạn giữa CSKH (tạo yêu cầu) và Kế toán (duyệt chi). Chặn hoàn toàn bypass ở tầng API/backend.
5. **Audit Logging & PCI-DSS Masking**: Cấu trúc chuẩn 9 trường. Tự động đè regex che giấu PAN (`************last4`) và triệt tiêu hoàn toàn trường CVV/CVC.
6. **Session Revocation**: Hỗ trợ hủy đơn lẻ và hủy toàn bộ session (`revoke_all_user_sessions`) thông qua Redis Set indexing.
