# BÁO CÁO THI GIỮA KỲ: AN TOÀN THƯƠNG MẠI ĐIỆN TỬ (LAB 01)
## Cổng Quản Trị & Luồng Hoàn Tiền Bảo Mật (Secure Admin & Refund Portal)

Dự án triển khai và kiểm chứng toàn diện **06 kiểm soát an ninh cốt lõi** và **08 test case bắt buộc (T1 – T8)** cho cổng quản trị sàn TMĐT, phân quyền nghiêm ngặt giữa CSKH, Kế toán và Admin trong luồng hoàn tiền nhạy cảm.

---

## 1. Kiến Trúc Hệ Thống & Quyết Định Bảo Mật (Security Architecture Decisions)

Hệ thống được thiết kế theo nguyên lý Phòng thủ theo chiều sâu (Defense-in-Depth) với backend Python FastAPI kết hợp in-memory store Redis 7 và cơ sở dữ liệu quan hệ SQLAlchemy (SQLite/PostgreSQL):

```text
[ Client (Browser / Postman / Tests) ]
                  │
                  ▼
       [ FastAPI Gateway / Uvicorn ]
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
[ Redis 7 In-Memory ]  [ SQLAlchemy ORM ]
- Atomic Anti-Replay   - SQLite DB (data/ecommerce.db)
- Session Store & TTL  - Users & Refund Requests
- Bulk Revocation Sets - Status & Masked PAN (last-4)
```

### 1.1. TOTP RFC 6238 (Chuẩn hóa xác thực 2 lớp)
- **Cơ chế**: Triển khai thuật toán HMAC-based One-Time Password dựa trên thời gian theo chuẩn RFC 6238, sử dụng bước nhảy thời gian cố định $T_0 = 30\text{s}$, độ dài 6 chữ số thập phân (`pyotp.TOTP`).
- **Dung sai độ lệch đồng hồ (Clock Drift)**: Cho phép cửa sổ $\pm 1$ step (tổng cửa sổ 90 giây: $T-1$, $T$, $T+1$) nhằm bù đắp sai số đồng hồ giữa client và server. Các mã ngoài cửa sổ này lập tức bị từ chối.
- **Bảo mật Secret**: Khóa bí mật (`totp_secret`) được mã hóa và lưu trữ an toàn trong DB; tuyệt đối **không ghi log, không trả về API** và được bảo vệ để tránh rò rỉ qua stacktrace.

### 1.2. Chống Tái Sử Dụng OTP Bằng Redis (Anti-Replay via Atomic Lock)
- **Vấn đề**: Trong cửa sổ 30s–90s, một OTP hợp lệ có thể bị kẻ tấn công nghe lén (Man-in-the-Middle) và gửi lại nhiều lần (Replay Attack).
- **Quyết định**: Sau khi hàm `verify_totp` xác thực thành công, hệ thống xác định chính xác time-step đã khớp $T_{match}$ và thực thi lệnh nguyên tử của Redis:
  ```text
  SET otp_replay:{user_id}:{time_step} "consumed" EX 90 NX
  ```
  - `NX`: Chỉ ghi nếu key chưa tồn tại. Nếu key đã có, lệnh trả về `None/False` -> Hệ thống lập tức trả về `401 Unauthorized` với mã lỗi `REPLAY_DETECTED` và ghi log kiểm toán.
  - `EX 90`: TTL 90 giây bao phủ toàn bộ cửa sổ chấp nhận $(\pm 1\text{ step})$. Sau 90s, mã OTP đó tự động hết hạn về mặt toán học.

### 1.3. Session Hardening & Chống Session Fixation
- **Cookie Security Flags**: Cấu hình `HttpOnly=True` (chặn XSS đánh cắp cookie qua `document.cookie`), `SameSite=Lax` (ngăn chặn CSRF), `Secure=False/True` (tự động kích hoạt khi dùng HTTPS trên production).
- **Session Rotation (Xoay Session ID)**:
  - Khi đăng nhập password thành công, hệ thống chỉ cấp session tạm thời `pre_mfa` (chưa có quyền hạn nghiệp vụ, TTL 5 phút).
  - Ngay khi MFA thành công, hệ thống lập tức **hủy bỏ hoàn toàn `pre_mfa` session** và sinh ra Session ID mới (256-bit mật mã học an toàn qua `secrets.token_urlsafe(32)`).
  - Ngăn chặn hoàn toàn kẻ tấn công cài đặt trước Session ID cho nạn nhân (Session Fixation Defense). Request dùng Session ID cũ sẽ nhận `401 Unauthorized`.
- **Ràng Buộc Thời Gian Sống (Timeouts)**:
  - **Idle Timeout**: 15 phút không có thao tác (được reset qua `touch_session`).
  - **Absolute Timeout**: 8 giờ tối đa kể từ thời điểm đăng nhập, không thể gia hạn thêm.

### 1.4. Phân Quyền RBAC & Tách Biệt Nhiệm Vụ (Segregation of Duties - SoD)
- **Nguyên tắc**: Chức năng hoàn tiền là giao dịch tài chính nhạy cảm, dễ xảy ra thông đồng hoặc lạm quyền nội bộ.
- **Kiểm soát SoD bắt buộc**:
  - **CSKH (`CSKH`)**: Chỉ có quyền tạo yêu cầu hoàn tiền (`POST /api/v1/refunds`), ở trạng thái `PENDING`. Tuyệt đối không có quyền duyệt chi.
  - **Kế toán (`KETOAN`)**: Chỉ có quyền duyệt chi hoàn tiền (`POST /api/v1/refunds/{id}/approve`), chuyển trạng thái sang `APPROVED`.
- **Enforcement tại Backend**: Ràng buộc qua dependency injection (`require_role`) kiểm tra trực tiếp trên API server. CSKH cố tình gọi endpoint duyệt chi sẽ nhận ngay `403 Forbidden` và sinh sự kiện audit `result=DENIED`.

### 1.5. Audit Logging & Che Giấu Dữ Liệu Nhạy Cảm (PCI-DSS & Data Masking)
- **Đủ 9 trường truy vết tối thiểu bắt buộc**:
  1. `timestamp`: Thời gian chuẩn ISO 8601 UTC.
  2. `actor_id`: ID người dùng (hoặc `None` nếu unauthenticated).
  3. `role`: Vai trò (`CSKH`, `KETOAN`, `ADMIN`, `ANONYMOUS`).
  4. `action`: Tên hành động (`LOGIN_PASSWORD_OK`, `MFA_SUCCESS`, `REFUND_CREATE`, `RBAC_ACCESS_DENIED`, ...).
  5. `object_id`: Định danh đối tượng thao tác.
  6. `result`: Kết quả thực thi (`SUCCESS`, `FAILED`, `DENIED`, `REPLAY_DETECTED`).
  7. `source_ip`: IP của client.
  8. `correlation_id`: Mã UUIDv4 xuyên suốt vòng đời request.
  9. `session_id_hash`: Mã băm SHA-256 của Session ID (đảm bảo log có thể đối soát nhưng kẻ đọc trộm log không thể dùng để giả mạo session).
- **Khử lộ lọt dữ liệu thẻ thanh toán (PCI-DSS)**:
  - Trường `PAN` (số thẻ tín dụng 13-19 số): Được mask tự động qua regex thành `************last4`. Trong database chỉ lưu 4 số cuối (`pan_last4`).
  - Trường `CVV/CVC`: **Triệt tiêu hoàn toàn ngay tại controller và logger**, tuyệt đối không lưu vào Database và không xuất hiện trong log file.

### 1.6. Thu Hồi Phiên (Session Revocation & Bulk Invalidation)
- Hủy session lập tức khi người dùng bấm Đăng xuất (`POST /auth/logout`), đổi mật khẩu, hoặc hệ thống phát hiện bất thường.
- Cơ chế quản lý theo User Set trong Redis (`user_sessions:{user_id}`) cho phép thực hiện **Revoke All Sessions** (hủy toàn bộ phiên đang hoạt động của tài khoản đó trên mọi thiết bị).

---

## 2. Bảng Đối Chiếu 8 Test Case Bắt Buộc (T1 - T8) & Bằng Chứng (Evidence)

| Mã | Tên Test Case | Mô Tả & Cách Thực Hiện | Điều Kiện Đạt (PASS) | Kết Quả Thực Tế | File Bằng Chứng JSON |
|:---:|:---|:---|:---|:---:|:---:|
| **T1** | **TOTP hợp lệ** | Login password -> gửi OTP đúng lần đầu | HTTP 200, MFA state = verified | **PASS** | [`evidence/T1_totp_valid.json`](./evidence/T1_totp_valid.json) |
| **T2** | **Replay OTP** | Gửi lại đúng OTP của T1 trong cùng time-step | HTTP 401/403; event `REPLAY_DETECTED` | **PASS** | [`evidence/T2_replay_detected.json`](./evidence/T2_replay_detected.json) |
| **T3** | **OTP sai / hết hạn** | Gửi OTP sai (`000000`) hoặc ngoài cửa sổ | HTTP 401; từ chối tạo session đặc quyền | **PASS** | [`evidence/T3_otp_invalid_expired.json`](./evidence/T3_otp_invalid_expired.json) |
| **T4** | **Session Fixation** | So sánh SID trước và sau khi hoàn tất MFA | `SID_before != SID_after`; SID cũ nhận 401 | **PASS** | [`evidence/T4_session_fixation.json`](./evidence/T4_session_fixation.json) |
| **T5** | **RBAC bypass** | CSKH gọi trực tiếp API approve refund | HTTP 403; audit `result=DENIED` | **PASS** | [`evidence/T5_rbac_bypass_denied.json`](./evidence/T5_rbac_bypass_denied.json) |
| **T6** | **Luồng SoD hợp lệ** | CSKH tạo refund; Kế toán duyệt refund | Cả 2 request 200/201; sinh 2 audit events | **PASS** | [`evidence/T6_refund_flow_valid.json`](./evidence/T6_refund_flow_valid.json) |
| **T7** | **Log masking** | Gửi payload chứa số thẻ PAN và CVV | Không có CVV; PAN mask `************last4` | **PASS** | [`evidence/T7_log_masking.json`](./evidence/T7_log_masking.json) |
| **T8** | **Session revocation** | Logout, sau đó gọi lại API bằng session cũ | HTTP 401; Redis xóa sạch session key | **PASS** | [`evidence/T8_session_revocation.json`](./evidence/T8_session_revocation.json) |

---

## 3. Danh Sách Tài Khoản Thử Nghiệm Mặc Định (Seed Users)

| Username | Password | Role | TOTP Secret (RFC 3548 Base32) |
|:---|:---|:---|:---|
| `cskh_user` | `Password123!` | `CSKH` | `JBSWY3DPEHPK3PXP` |
| `ketoan_user` | `Password123!` | `KETOAN` | `HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ` |
| `admin_user` | `AdminPassword123!` | `ADMIN` | `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` |

---

## 4. Hướng Dẫn Cài Đặt & Khởi Chạy (Deployment Guide)

### Cách 1: Khởi chạy bằng Docker Compose (Khuyến nghị)
Hệ thống đã được đóng gói sẵn toàn bộ ứng dụng web và Redis container với cơ chế healthcheck tự động:

```bash
# 1. Di chuyển vào thư mục dự án
cd "/home/tcus/Desktop/An toan thuong mai dien tu"

# 2. Khởi chạy Docker Compose (sử dụng sudo mật khẩu root123 nếu cần)
docker compose up --build -d

# 3. Kiểm tra trạng thái containers và healthcheck
docker compose ps

# 4. Xem log audit trực tiếp
docker compose logs -f web
```

*Lưu ý về Port Mapping*:
- Ứng dụng web chạy tại: `http://localhost:8000` (OpenAPI Swagger UI: `http://localhost:8000/docs`).
- Redis container ánh xạ cổng host `6380:6379` (hoặc cấu hình qua biến `REDIS_PORT` trong `.env`) để tránh xung đột nếu máy trạm đã có Redis native chạy trên port 6379. Ứng dụng web trong Docker kết nối với Redis qua mạng nội bộ `redis://redis:6379/0`.

Dừng hệ thống:
```bash
docker compose down
```

---

### Cách 2: Khởi chạy trực tiếp trên môi trường Local (Host)

Yêu cầu: Python 3.10+, Redis server đang chạy (`redis-cli ping` trả về `PONG`).

```bash
# 1. Cài đặt thư viện phụ thuộc
pip install -r requirements.txt

# 2. Khởi tạo cơ sở dữ liệu và seed tài khoản mặc định
python3 scripts/seed_db.py

# 3. Chạy server uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 5. Hướng Dẫn Chạy Bộ Test Tự Động & Thu Thập Evidence

Hệ thống cung cấp sẵn các phương thức kiểm thử tự động toàn diện:

### 5.1. Chạy E2E Test Suite và tự động xuất file Evidence
Script kiểm thử độc lập sẽ chạy tuần tự từ T1 đến T8, kiểm tra mã HTTP, phản hồi JSON, trạng thái Redis in-memory và kiểm tra file log:

```bash
python3 scripts/run_e2e_tests.py
```

Kết quả:
- Màn hình console in chi tiết từng bước kiểm thử và trạng thái `PASS`.
- Toàn bộ bằng chứng được ghi đè vào thư mục `evidence/` (`T1_totp_valid.json` -> `T8_session_revocation.json` và `SUMMARY.md`).

### 5.2. Chạy qua PyTest
```bash
# Chạy bộ test E2E T1-T8
pytest tests/test_e2e_security.py -v

# Chạy toàn bộ 30 test cases bao gồm cả Adversarial Stress-Tests
pytest tests/ -v
```

### 5.3. Sử dụng Postman Collection
- Import file [`postman_collection.json`](./postman_collection.json) vào ứng dụng Postman.
- Đặt biến môi trường `baseUrl`: `http://localhost:8000/api/v1`.
- Chạy lần lượt các request tương ứng để trực quan hóa luồng nghiệp vụ.

---

## 6. Cấu Trúc Thư Mục Dự Án (Repository Structure)

```text
.
├── Dockerfile                   # Docker container build script (hardened non-root user)
├── docker-compose.yml           # Docker Compose orchestrating App + Redis
├── requirements.txt             # Danh sách dependencies
├── .env.example                 # Mẫu cấu hình môi trường
├── README.md                    # Tài liệu hướng dẫn & mô tả bảo mật
├── postman_collection.json      # Postman Collection cho 8 test case
├── app/
│   ├── main.py                  # Entrypoint FastAPI, CORS, middleware, lifespan
│   ├── core/
│   │   ├── config.py            # Pydantic Settings quản lý timeouts & cấu hình
│   │   ├── security.py          # TOTP RFC 6238, Argon2id, Session Token generation
│   │   ├── redis.py             # Atomic SET NX anti-replay, session storage & revocation
│   │   └── audit.py             # 9-field audit logger, regex PAN masking, CVV elimination
│   ├── db/
│   │   ├── database.py          # SQLAlchemy engine & session maker
│   │   ├── models.py            # ORM User và RefundRequest
│   │   └── seed.py              # Script seed tài khoản CSKH, Kế toán, Admin
│   ├── middleware/
│   │   └── correlation.py       # Middleware sinh UUIDv4 correlation_id
│   ├── schemas/
│   │   ├── auth.py              # Pydantic schemas cho đăng nhập & xác thực
│   │   └── refund.py            # Pydantic schemas cho luồng hoàn tiền
│   └── api/
│       ├── deps.py              # Session validation & require_role RBAC guard
│       └── v1/
│           ├── auth.py          # /login, /mfa/verify, /logout, /revoke-all, /me
│           ├── refunds.py       # /refunds (CSKH create), /refunds/{id}/approve (KETOAN)
│           └── admin.py         # /admin/audit-logs, /admin/users
├── tests/
│   ├── test_e2e_security.py     # Bộ kiểm thử PyTest 8/8 test cases T1-T8
│   ├── test_adversarial_auth.py # Adversarial stress tests cho Auth & Session
│   └── test_adversarial_rbac_sod.py # Adversarial stress tests cho RBAC & SoD
├── scripts/
│   ├── seed_db.py               # CLI tool seed DB
│   └── run_e2e_tests.py         # Harness chạy E2E và trích xuất evidence T1-T8
├── logs/
│   └── audit.log                # File lưu log kiểm toán cấu trúc JSON
└── evidence/
    ├── SUMMARY.md               # Báo cáo tổng hợp kiểm chứng bảo mật
    ├── T1_totp_valid.json
    ├── T2_replay_detected.json
    ├── T3_otp_invalid_expired.json
    ├── T4_session_fixation.json
    ├── T5_rbac_bypass_denied.json
    ├── T6_refund_flow_valid.json
    ├── T7_log_masking.json
    └── T8_session_revocation.json
```

