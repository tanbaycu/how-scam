# scam-guardian

Sandbox phân tích website lừa đảo tự động, viết bằng Go.

> Dự án này được xây dựng trong quá trình học tập và nghiên cứu về phòng chống tội phạm công nghệ cao.

---

## Vấn đề cần giải quyết

Mỗi ngày có hàng nghìn trang web giả mạo ngân hàng, ví điện tử, mạng xã hội được dựng lên để lừa đảo người dùng. Quy trình xử lý hiện tại phần lớn là **thủ công**: ai đó báo cáo link → người phân tích mở link → chụp ảnh → tra WHOIS → soạn email gửi nhà mạng yêu cầu gỡ. Quá trình này mất **hàng giờ đồng hồ** cho mỗi trang.

**scam-guardian** rút gọn toàn bộ quy trình đó xuống còn **một lệnh duy nhất**.

---

## Hệ thống làm gì

```
URL nghi ngờ
    │
    ▼
┌───────────────────────────────┐
│  1. SANDBOX                   │
│  Chrome headless cách ly      │
│  Render JS, bắt network req   │
│  Chụp ảnh toàn trang          │
│  Lưu mã nguồn HTML            │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│  2. PHÂN TÍCH                 │
│  Quét form: password/OTP/card │
│  Bắt POST request → C2 EP    │
│  Phát hiện anti-debug script  │
│  Nhận diện brand bị giả mạo  │
│  Tính Risk Score 0-100        │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│  3. RECONNAISSANCE            │
│  SSL cert age & issuer check  │
│  Typosquatting detection      │
│  (Levenshtein + homoglyph)    │
│  WHOIS → registrar + abuse    │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│  4. ĐẦU RA                   │
│  screenshot.png               │
│  page_source.html             │
│  report.json (structured)     │
│  abuse_report.txt (takedown)  │
└───────────────────────────────┘
```

---

## Từng phần hoạt động như thế nào

### Sandbox trình duyệt

Tại sao không dùng `curl` hay thư viện HTTP đơn giản? Vì các trang phishing hiện đại **render nội dung bằng JavaScript**. Form đăng nhập giả có thể không tồn tại trong mã HTML gốc — nó được inject động sau khi JS chạy xong. Một số trang còn kiểm tra User-Agent, viewport size, hoặc cookie trước khi hiển thị nội dung lừa đảo.

scam-guardian giải quyết bằng cách khởi chạy một instance **Chromium thật** (không phải trình giả lập) trong container Docker cách ly. Trình duyệt này:

- Chạy đầy đủ V8 engine, render DOM y như người dùng thật mở trang
- Bật **CDP Network Domain** để nghe lén mọi HTTP request mà trang web gửi đi. Bất kỳ POST request nào hoặc request nào có chứa từ khóa `api` đều bị ghi nhận lại — đây thường là endpoint mà hacker dùng để nhận dữ liệu bị đánh cắp (gọi là **exfiltration endpoint** hay C2)
- Chụp screenshot toàn trang làm bằng chứng số
- Lưu toàn bộ HTML source sau khi JS đã chạy xong

### Phát hiện dấu hiệu lừa đảo (Heuristic Engine)

Sau khi có DOM hoàn chỉnh, hệ thống quét các dấu hiệu:

**Form nhạy cảm:** Duyệt qua tất cả thẻ `<form>`, lấy danh sách các `<input>` bên trong. Nếu tên hoặc ID của input chứa các pattern như `pass`, `otp`, `cvv`, `cccd`, `ssn` — đó là form thu thập thông tin nhạy cảm. Mỗi loại được gán một mức điểm rủi ro khác nhau (password: +40, card: +30, OTP: +30, PII: +25).

**Kỹ thuật trốn tránh của hacker:** Nhiều trang phishing cài JavaScript để chặn nhấp chuột phải (`contextmenu`), phát hiện và đóng DevTools (`devtools`, `debugger`), hoặc tắt console (`console.log=`). Sự hiện diện của các đoạn mã này làm tăng mức nghi ngờ.

**Thương hiệu bị nhắm tới:** Quét nội dung trang để tìm tên các thương hiệu hay bị giả mạo — từ PayPal, Binance, MetaMask cho đến Vietcombank, MoMo, ZaloPay. Nếu trang web không thuộc domain chính thức của thương hiệu đó nhưng lại chứa nội dung liên quan → đây là dấu hiệu impersonation.

### Phát hiện Typosquatting

Typosquatting là kỹ thuật đăng ký domain giống domain thật nhưng khác một vài ký tự. Ví dụ:
- `paypa1.com` thay vì `paypal.com` (chữ `l` → số `1`)
- `faceb00k.com` thay vì `facebook.com` (chữ `o` → số `0`)
- `vietc0mbank.com` thay vì `vietcombank.com`

Hệ thống phát hiện bằng 2 bước:
1. **Chuẩn hóa homoglyph:** Thay thế các ký tự hay bị lạm dụng (`0`→`o`, `1`→`l`, `@`→`a`, v.v.) để lấy domain "thật" mà hacker muốn giả mạo
2. **So sánh Levenshtein:** Tính khoảng cách chỉnh sửa giữa domain đã chuẩn hóa với danh sách thương hiệu. Nếu similarity ≥ 65% thì cảnh báo

### Phân tích chứng chỉ SSL

Các trang phishing thường có đặc điểm SSL rất khác biệt so với trang thật:
- Chứng chỉ **mới toanh** (dưới 7 ngày) → domain vừa được tạo ra
- Sử dụng nhà cấp **miễn phí** (Let's Encrypt, ZeroSSL) — không phải lỗi của nhà cấp, nhưng phishing lạm dụng chúng rất nhiều vì không cần xác minh danh tính
- Chứng chỉ **tự ký** (self-signed) → cực kỳ đáng ngờ

### WHOIS & Takedown

Khi Risk Score ≥ 40, hệ thống:
1. Truy vấn WHOIS để tìm nhà đăng ký tên miền (registrar), email tiếp nhận báo cáo lạm dụng (abuse contact), ngày đăng ký domain
2. Tự động soạn một email takedown request bằng tiếng Anh chuẩn, kèm đầy đủ bằng chứng kỹ thuật (risk score, danh sách IoC, exfiltration endpoints) để gửi cho đội ngũ abuse của nhà mạng

### Xuất dữ liệu có cấu trúc (JSON)

Toàn bộ kết quả phân tích được xuất ra file `report.json` với verdict rõ ràng (`CLEAN`, `SUSPICIOUS`, `CONFIRMED_PHISHING`). File này có thể được import trực tiếp vào các hệ thống SIEM (Splunk, ELK) hoặc feed vào pipeline xử lý tự động của tổ chức.

---

## Sử dụng

### Quét 1 URL
```bash
docker compose run --rm scam-guardian https://suspicious-site.com
```

### Quét hàng loạt từ file
```bash
# urls.txt — mỗi dòng 1 URL
docker compose run --rm scam-guardian --batch urls.txt
```

### Chạy như API server
```bash
docker compose run --rm -p 8080:8080 scam-guardian --serve :8080

# Gọi API
curl "http://localhost:8080/scan?url=https://suspicious-site.com"
```

### Kết quả đầu ra (thư mục `output/`)

| File | Nội dung |
|---|---|
| `screenshot.png` | Ảnh chụp giao diện trang web thực tế |
| `page_source.html` | Mã nguồn HTML sau khi JS đã render |
| `report.json` | Báo cáo phân tích đầy đủ (JSON structured) |
| `abuse_report.txt` | Email takedown soạn sẵn gửi nhà mạng |
| `batch_results.json` | Tổng hợp kết quả khi quét hàng loạt |

---

## Yêu cầu

- Docker
- Hoặc Go 1.21+ và Chromium (nếu chạy trực tiếp)

---

## Cấu trúc mã nguồn

```
.
├── main.go          # Entry point, sandbox browser, batch/API modes
├── detector.go      # Heuristic engine phân tích DOM & form
├── recon.go         # SSL inspection, typosquatting detection
├── takedown.go      # WHOIS lookup, abuse report, JSON export
├── Dockerfile       # Multi-stage build (Go builder → Debian slim)
└── docker-compose.yml
```
