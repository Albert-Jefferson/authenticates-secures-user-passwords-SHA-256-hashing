# SHA-256 Authentication System

Hệ thống xác thực và bảo mật mật khẩu người dùng bằng SHA-256 kết hợp salt, được xây dựng bằng Python Flask và SQLite cho học phần **Mật mã học cơ sở**.

Project minh họa luồng đăng ký, đăng nhập, lưu mật khẩu dưới dạng hash, xác thực bằng cách băm lại mật khẩu nhập vào và so sánh giá trị hash thay vì lưu/so sánh mật khẩu gốc.

## Mục tiêu đề tài

Đề tài số 6: **Thiết kế hệ thống xác thực và bảo mật mật khẩu người dùng bằng thuật toán băm SHA-256**.

Các mục tiêu chính:

- Tìm hiểu vai trò của hàm băm mật mã trong bảo vệ mật khẩu.
- Sử dụng SHA-256 trong quá trình tạo giá trị băm mật khẩu.
- Kết hợp salt ngẫu nhiên để chống rainbow table và giảm rủi ro hash trùng nhau.
- Xây dựng hệ thống đăng ký, đăng nhập và xác thực người dùng.
- Lưu thông tin người dùng trong SQLite mà không lưu mật khẩu gốc.
- Minh họa kiểm thử với salt/no salt và brute-force/dictionary attack đơn giản.

## Tính năng chính

- Đăng ký tài khoản với username/password.
- Kiểm tra định dạng username.
- Kiểm tra độ mạnh mật khẩu.
- Sinh salt ngẫu nhiên 32 bytes bằng `os.urandom()`.
- Băm mật khẩu bằng `PBKDF2-HMAC-SHA256`.
- Lưu hash theo định dạng có version để dễ nâng cấp.
- Đăng nhập bằng cách băm lại mật khẩu nhập vào và so sánh hash.
- So sánh hash bằng `hmac.compare_digest()` để giảm rủi ro timing attack.
- Không tiết lộ username không tồn tại khi đăng nhập, giúp giảm user enumeration.
- Cấp token phiên đăng nhập demo.
- Đổi mật khẩu sau khi đăng nhập.
- Logout và xóa token khỏi bộ nhớ demo.
- Endpoint xem thông tin user hiện tại.
- Endpoint danh sách người dùng ẩn dữ liệu nhạy cảm.
- Log sự kiện bảo mật.
- Rate limiting cho API.
- Khóa tài khoản tạm thời sau nhiều lần đăng nhập sai.
- Giao diện web demo bằng Flask template.
- Script demo minh họa salt, hash, kiểm tra mật khẩu và brute-force.
- Unit test cho module hash và API.

## Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3.10+ |
| Web framework | Flask |
| Database | SQLite |
| Hashing | `hashlib`, `hashlib.pbkdf2_hmac` |
| So sánh an toàn | `hmac.compare_digest` |
| CORS | Flask-CORS |
| Rate limit | Flask-Limiter |
| Testing | pytest, unittest |
| Giao diện | HTML/CSS/JavaScript trong `templates/index.html` |

## Vì sao dùng PBKDF2-HMAC-SHA256?

Yêu cầu đề tài tập trung vào SHA-256. Trong project này, SHA-256 được dùng làm hàm băm lõi bên trong `PBKDF2-HMAC-SHA256`.

Thay vì chỉ tính một lần:

```text
SHA-256(salt + password)
```

hệ thống chính dùng:

```text
PBKDF2-HMAC-SHA256(password + pepper, salt, iterations=100000)
```

Cách này an toàn hơn SHA-256 thuần một vòng vì:

- Tăng chi phí tính toán cho mỗi lần thử mật khẩu.
- Làm brute-force/dictionary attack chậm hơn.
- Vẫn sử dụng SHA-256 làm thành phần băm cốt lõi.
- Cho phép tăng số vòng lặp trong tương lai.

File `hash256_salt.py` vẫn được giữ lại để minh họa đúng công thức SHA-256 thuần kết hợp salt theo yêu cầu học thuật.

## Cấu trúc thư mục

```text
.
├── app.py
├── Database.py
├── password_hasher.py
├── hash256_salt.py
├── demo.py
├── API_endpoint.txt
├── requirements.txt
├── test_api.py
├── test_password_hasher.py
├── wordlist-demo.txt
├── users.db
├── templates/
│   └── index.html
└── KỊCH BẢN KIỂM THỬ TẤN CÔNG BRUTE‑FORCE.docx
```

## Vai trò từng file

### `app.py`

Flask web app và REST API chính của hệ thống.

Chức năng:

- Khởi tạo Flask app.
- Cấu hình CORS và rate limit.
- Render giao diện `templates/index.html`.
- Xử lý đăng ký, đăng nhập, logout, đổi mật khẩu.
- Xác thực Bearer token.
- Trả thông tin user hiện tại.
- Trả danh sách user đã ẩn thông tin nhạy cảm.
- Trả log bảo mật gần nhất.

### `Database.py`

Tầng xử lý SQLite.

Chức năng:

- Khởi tạo database và bảng.
- Lưu user mới.
- Tìm user khi đăng nhập.
- Cập nhật số lần đăng nhập sai.
- Khóa tài khoản tạm thời.
- Cập nhật mật khẩu mới.
- Truy vấn thông tin user an toàn.
- Truy vấn danh sách user an toàn.
- Ghi log sự kiện bảo mật.

### `password_hasher.py`

Module bảo mật mật khẩu chính.

Chức năng:

- `generate_salt()`: sinh salt ngẫu nhiên.
- `hash_password()`: hash password bằng PBKDF2-HMAC-SHA256.
- `verify_password()`: xác thực password bằng cách hash lại và so sánh.
- `validate_password()`: kiểm tra độ mạnh password.
- `register_password()`: validate, sinh salt và hash password.
- `change_password()`: đổi mật khẩu an toàn.
- `needs_rehash()`: kiểm tra hash cũ có cần nâng cấp không.
- `RateLimiter`: rate limiter đơn giản theo username.

### `hash256_salt.py`

File minh họa SHA-256 thuần kết hợp salt.

Công thức minh họa:

```text
SHA-256(salt + password)
```

File này phục vụ giải thích lý thuyết trong báo cáo và so sánh với hệ thống chính.

### `demo.py`

Script demo trên terminal.

Nội dung minh họa:

- Tạo salt ngẫu nhiên.
- Băm mật khẩu.
- So sánh khi có salt và không có salt.
- Kiểm tra độ mạnh mật khẩu.
- Mô phỏng đăng ký/đăng nhập.
- Chứng minh hash không chứa mật khẩu gốc.
- Demo brute-force/dictionary attack bằng `wordlist-demo.txt`.

### `templates/index.html`

Giao diện web demo.

Chức năng:

- Form đăng ký.
- Form đăng nhập.
- Hiển thị trạng thái phiên.
- Xem thông tin user hiện tại.
- Xem danh sách người dùng đã ẩn hash/salt/password.
- Logout.

### `test_password_hasher.py`

Test cho module hash mật khẩu.

Bao gồm:

- Test sinh salt.
- Test hash password.
- Test verify password.
- Test kiểm tra độ mạnh mật khẩu.
- Test đổi mật khẩu.
- Test rehash.
- Test pepper.
- Test PBKDF2 iterations.
- Test rate limiter.

### `test_api.py`

Test cho Flask API.

Bao gồm:

- Đăng ký thành công.
- Username trùng.
- Request thiếu field.
- Password yếu.
- Đăng nhập thành công.
- Đăng nhập sai.
- Đổi mật khẩu.
- Logout.
- Lấy thông tin user hiện tại.
- Rate limit/error handling.

## Cơ chế bảo mật mật khẩu

### 1. Không lưu mật khẩu gốc

Khi user đăng ký, hệ thống không lưu password dạng plaintext. Thay vào đó, hệ thống lưu chuỗi `stored_value` chứa thông tin cần thiết để xác thực về sau.

Ví dụ định dạng:

```text
sha256v2$<salt_hex>$<iterations>$<pepper_flag>$<hash_hex>
```

Ý nghĩa:

- `sha256v2`: version của định dạng lưu trữ.
- `salt_hex`: salt ngẫu nhiên dạng hex.
- `iterations`: số vòng PBKDF2.
- `pepper_flag`: cho biết hash có dùng pepper hay không.
- `hash_hex`: hash kết quả cuối cùng.

### 2. Salt

Salt là giá trị ngẫu nhiên được sinh riêng cho mỗi user.

Trong project:

- Salt dài 32 bytes.
- Được sinh bằng `os.urandom()`.
- Được lưu cùng hash trong database.

Salt giúp:

- Hai user có cùng password vẫn tạo ra hash khác nhau.
- Giảm hiệu quả của rainbow table.
- Buộc attacker phải tính toán lại hash cho từng salt riêng biệt.

### 3. Pepper

Pepper là một chuỗi bí mật bổ sung vào quá trình hash.

Trong project:

```text
PASSWORD_PEPPER
```

được đọc từ biến môi trường. Nếu không cấu hình, project dùng giá trị development để chạy demo.

Trong production, cần cấu hình pepper riêng và không lưu pepper trong database.

### 4. PBKDF2-HMAC-SHA256

Hệ thống dùng `hashlib.pbkdf2_hmac()` với:

- Hash algorithm: SHA-256.
- Salt: salt riêng của user.
- Iterations: `100000`.
- Output length: 32 bytes.

Điều này giúp tăng chi phí brute-force so với SHA-256 thuần.

### 5. So sánh constant-time

Khi đăng nhập, hệ thống không dùng toán tử `==` để so sánh hash. Thay vào đó dùng:

```python
hmac.compare_digest(candidate, original_hash)
```

Điều này giúp giảm rủi ro timing attack.

## Luồng hoạt động

### Luồng đăng ký

```text
User nhập username/password
        │
        ▼
Validate username/password
        │
        ▼
Kiểm tra username đã tồn tại chưa
        │
        ▼
Sinh salt ngẫu nhiên 32 bytes
        │
        ▼
Hash password bằng PBKDF2-HMAC-SHA256
        │
        ▼
Lưu username + stored_value vào SQLite
        │
        ▼
Trả về user_id và thông báo đăng ký thành công
```

### Luồng đăng nhập

```text
User nhập username/password
        │
        ▼
Tìm user theo username
        │
        ▼
Lấy stored_value đã lưu
        │
        ▼
Parse salt, iterations, pepper_flag, hash gốc
        │
        ▼
Hash lại password người dùng nhập
        │
        ▼
So sánh candidate_hash với original_hash bằng hmac.compare_digest
        │
        ▼
Nếu đúng: tạo token demo và reset failed_attempts
Nếu sai: tăng failed_attempts và có thể khóa tài khoản
```

## Cài đặt

### 1. Clone repo

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Tạo môi trường ảo

Trên Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Trên macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Cài dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Cấu hình biến môi trường khuyến nghị

Trên Windows PowerShell:

```powershell
$env:SECRET_KEY="change-this-secret-key"
$env:PASSWORD_PEPPER="change-this-password-pepper"
```

Trên macOS/Linux:

```bash
export SECRET_KEY="change-this-secret-key"
export PASSWORD_PEPPER="change-this-password-pepper"
```

Nếu không cấu hình, project vẫn chạy được ở chế độ demo/development, nhưng không nên dùng cấu hình mặc định cho production.

## Chạy ứng dụng

```bash
python app.py
```

Mặc định server chạy tại:

```text
http://localhost:5000
```

Mở trình duyệt và truy cập:

```text
http://localhost:5000/
```

## Chạy demo terminal

```bash
python demo.py
```

Demo sẽ minh họa:

- Salt ngẫu nhiên.
- Hash mật khẩu.
- Khác biệt giữa hash có salt và không có salt.
- Kiểm tra độ mạnh mật khẩu.
- Đăng ký/đăng nhập mô phỏng.
- Hash không thể đảo ngược trực tiếp.
- Brute-force/dictionary attack với wordlist.

## Chạy test

```bash
python -m pytest -v
```

Chạy kèm coverage:

```bash
python -m pytest --cov=. -v
```

## API Endpoints

### 1. Đăng ký

```http
POST /api/auth/register
Content-Type: application/json
```

Request body:

```json
{
  "username": "nguyenhonga",
  "password": "Pass@1234"
}
```

Response thành công:

```json
{
  "success": true,
  "message": "Đăng ký thành công",
  "user_id": 1
}
```

Status code:

- `201`: đăng ký thành công.
- `400`: request không hợp lệ hoặc password yếu.
- `409`: username đã tồn tại.
- `500`: lỗi hệ thống.

### 2. Đăng nhập

```http
POST /api/auth/login
Content-Type: application/json
```

Request body:

```json
{
  "username": "nguyenhonga",
  "password": "Pass@1234"
}
```

Response thành công:

```json
{
  "success": true,
  "message": "Đăng nhập thành công",
  "token": "session-token",
  "expires_in": 3600
}
```

Status code:

- `200`: đăng nhập thành công.
- `400`: thiếu request hoặc request sai.
- `401`: sai thông tin đăng nhập hoặc tài khoản bị khóa.
- `500`: lỗi hệ thống.

### 3. Lấy thông tin user hiện tại

```http
GET /api/auth/me
Authorization: Bearer <token>
```

Response:

```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "nguyenhonga",
    "created_at": "2026-05-29 10:00:00",
    "updated_at": "2026-05-29 10:00:00",
    "last_login": "2026-05-29 10:05:00",
    "failed_attempts": 0,
    "is_active": true
  }
}
```

### 4. Danh sách người dùng

```http
GET /api/users
Authorization: Bearer <token>
```

Query optional:

```text
?limit=100
```

Response:

```json
{
  "success": true,
  "users": [
    {
      "id": 1,
      "username": "nguyenhonga",
      "created_at": "2026-05-29 10:00:00",
      "updated_at": "2026-05-29 10:00:00",
      "last_login": "2026-05-29 10:05:00",
      "failed_attempts": 0,
      "is_active": true
    }
  ]
}
```

Endpoint này không trả về:

- Password gốc.
- Salt.
- Hash.
- `stored_value`.
- Pepper.

### 5. Đổi mật khẩu

```http
POST /api/auth/change-password
Authorization: Bearer <token>
Content-Type: application/json
```

Request body:

```json
{
  "old_password": "Pass@1234",
  "new_password": "NewPass@5678"
}
```

Response thành công:

```json
{
  "success": true,
  "message": "Đổi mật khẩu thành công"
}
```

### 6. Đăng xuất

```http
POST /api/auth/logout
Authorization: Bearer <token>
```

Response:

```json
{
  "success": true,
  "message": "Đăng xuất thành công"
}
```

### 7. Security logs

```http
GET /api/security-logs
Authorization: Bearer <token>
```

Response:

```json
{
  "success": true,
  "logs": [
    {
      "id": 1,
      "username": "nguyenhonga",
      "event_type": "LOGIN_SUCCESS",
      "ip_address": "127.0.0.1",
      "details": null,
      "created_at": "2026-05-29 10:05:00"
    }
  ]
}
```

## Ví dụ dùng curl

### Đăng ký

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice@1234"}'
```

### Đăng nhập

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice@1234"}'
```

### Gọi endpoint cần token

```bash
curl http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer <token>"
```

## Database schema

### Bảng `users`

| Cột | Ý nghĩa |
|---|---|
| `id` | ID tự tăng của user |
| `username` | Tên đăng nhập, unique |
| `stored_value` | Chuỗi lưu hash/salt/version/iterations |
| `created_at` | Thời điểm tạo tài khoản |
| `updated_at` | Thời điểm cập nhật gần nhất |
| `failed_attempts` | Số lần đăng nhập sai |
| `locked_until` | Thời điểm khóa tài khoản hết hạn |
| `last_login` | Thời điểm đăng nhập gần nhất |
| `is_active` | Trạng thái tài khoản |

### Bảng `security_logs`

| Cột | Ý nghĩa |
|---|---|
| `id` | ID log |
| `username` | Username liên quan đến sự kiện |
| `event_type` | Loại sự kiện bảo mật |
| `ip_address` | IP request |
| `user_agent` | User-Agent của client |
| `details` | Chi tiết bổ sung dạng JSON |
| `created_at` | Thời điểm ghi log |

## Kiểm thử theo yêu cầu đề tài

### 1. Không thể khôi phục trực tiếp mật khẩu từ hash

Trong `demo.py`, hệ thống in ra password gốc và `stored_value`, sau đó kiểm tra password gốc không xuất hiện trong `stored_value`.

Kết luận: hash là một chiều, không thể đảo ngược trực tiếp để lấy password gốc. Attacker chỉ có thể đoán password, băm lại và so sánh.

### 2. So sánh có salt và không có salt

Demo minh họa:

- Không salt: cùng password tạo cùng hash.
- Có salt: cùng password nhưng salt khác nhau tạo hash khác nhau.

Điều này cho thấy salt giúp chống rainbow table và giảm rủi ro phát hiện user dùng chung password.

### 3. Brute-force/dictionary attack

`demo.py` đọc `wordlist-demo.txt` và thử từng password trong wordlist.

Quy trình:

```text
for candidate in wordlist:
    verify_password(candidate, target_stored_value)
```

Nếu password yếu nằm trong wordlist, attacker có thể tìm ra. Nếu password mạnh và không nằm trong wordlist, attacker thất bại trong phạm vi demo.

## Chính sách mật khẩu

Mật khẩu hợp lệ cần:

- Tối thiểu 8 ký tự.
- Tối đa 128 ký tự.
- Có ít nhất 1 chữ hoa.
- Có ít nhất 1 chữ thường.
- Có ít nhất 1 chữ số.
- Có ít nhất 1 ký tự đặc biệt.

Mức độ mạnh được đánh giá theo thang điểm 0-5:

- `Yếu`: từ 0 đến 2 điểm.
- `Trung bình`: từ 3 đến 4 điểm.
- `Mạnh`: 5 điểm.

## Rate limiting và khóa tài khoản

Hệ thống có hai lớp bảo vệ:

### 1. Flask-Limiter

Giới hạn request theo IP:

- Mặc định: `200 per day`, `50 per hour`.
- Register: `10 per minute`.
- Login: `20 per minute`.
- Change password: `5 per minute`.

### 2. Failed login lockout

Khi đăng nhập sai nhiều lần:

- Tối đa: `5` lần sai.
- Khóa tài khoản: `900` giây, tương đương 15 phút.

## Lưu ý bảo mật

Project này phục vụ học tập/demo, chưa nên dùng trực tiếp cho production nếu chưa bổ sung thêm các biện pháp sau:

- Dùng HTTPS.
- Dùng JWT/session storage an toàn thay cho token lưu trong RAM.
- Cấu hình `SECRET_KEY` và `PASSWORD_PEPPER` bằng biến môi trường mạnh.
- Không commit `users.db` thật lên GitHub.
- Không commit secret, token, password thật.
- Thêm CSRF protection nếu dùng form truyền thống.
- Tách database test và database production.
- Thêm migration thay vì tự tạo schema khi import.
- Thêm logging/monitoring production.
- Thêm cơ chế reset password an toàn.
- Thêm xác minh email nếu mở rộng thành hệ thống thực tế.

## Gợi ý `.gitignore`

Nên thêm hoặc kiểm tra `.gitignore` để tránh commit file nhạy cảm:

```gitignore
.venv/
__pycache__/
*.pyc
.env
users.db
*.sqlite3
.pytest_cache/
.coverage
htmlcov/
repomix-output-*.xml
```

## Kết quả đáp ứng yêu cầu đề tài

| Yêu cầu | Trạng thái |
|---|---|
| Nghiên cứu SHA-256/hash/salt | Có thể trình bày trong báo cáo và README |
| Giao diện đăng ký/đăng nhập | Có `templates/index.html` |
| Đăng ký tài khoản | Có |
| Sinh salt | Có |
| Băm mật khẩu | Có, dùng PBKDF2-HMAC-SHA256 |
| Lưu database | Có SQLite |
| Đăng nhập và xác thực hash | Có |
| Danh sách người dùng ẩn nhạy cảm | Có `/api/users` |
| So sánh có salt/không salt | Có trong `demo.py` |
| Brute-force demo | Có trong `demo.py` và `wordlist-demo.txt` |
| Test | Có `test_api.py`, `test_password_hasher.py` |

## Hướng phát triển

- Chuyển token demo sang JWT hoặc server-side session an toàn.
- Dùng Argon2id hoặc bcrypt cho production password hashing.
- Thêm Dockerfile và docker-compose.
- Thêm migration database.
- Thêm trang quản trị user.
- Thêm reset password qua email.
- Thêm kiểm thử end-to-end.
- Thêm CI GitHub Actions chạy test tự động.
- Thêm báo cáo PDF kèm hình ảnh luồng xử lý và kết quả demo.

## Tác giả

Project được xây dựng cho học phần **Mật mã học cơ sở** với mục tiêu minh họa hệ thống xác thực và bảo mật mật khẩu bằng SHA-256 kết hợp salt.

## License

Dự án phục vụ mục đích học tập. Có thể sử dụng, chỉnh sửa và mở rộng cho báo cáo/đồ án môn học.
