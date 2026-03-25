# ✅ Hoàn thành: OTP Web Server cho Render

## 🎯 Tóm tắt
- ✅ Web server hoàn chỉnh với **đăng nhập nhân viên**
- ✅ Telegram bot **không thay đổi** - vẫn chạy bình thường  
- ✅ Google Sheet **tự động đồng bộ**
- ✅ **24/7 hoạt động** trên Render
- ✅ Khóa bảo mật mạnh đã generate

## 📂 Files được tạo/cập nhật

| File | Trạng thái | Mô tả |
|------|-----------|-------|
| `otp/otp_web_server.py` | ✅ | Web server hoàn chỉnh, 545 dòng |
| `otp/run_otp_web.sh` | ✅ | Script startup tương thích Render |
| `render.yaml` | ✅ | Cấu hình Render blueprint |
| `otp/.env.local` | ✅ | Cập nhật khóa bảo mật |
| `.gitignore` | ✅ | Mới - bảo vệ nhạy cảm |
| `DEPLOY_RENDER_GUIDE.md` | ✅ | Hướng dẫn chi tiết |
| `deploy_to_render.sh` | ✅ | Script tự động prepare git |

## 🔐 Khóa bảo mật được Generate

| Khóa | Giá trị |
|-----|--------|
| `OTP_WEB_SESSION_SIGNING_KEY` | `2eb1ea0144440b5c7e0595daed812ffa49d06890a4cc34eaebdd805e4d287c1` |
| `OTP_WEB_API_KEY` | `2546757629050b04c57ace1f98049330e98e9e7b907c38d618497bbdcf049fd7` |

*(Đã được đặt vào `.env.local`)*

## 👥 Nhân viên test
- **Username:** `employee1`
- **Password:** `pass1`

## 🚀 Các bước tiếp theo

### 1️⃣ Chuẩn bị Git (1 lần)
```bash
cd /Users/xz/Desktop/aaa
git init
git config user.email "your-email@example.com"
git config user.name "Your Name"
```

### 2️⃣ Commit và đẩy lên GitHub
```bash
git add -A
git commit -m "Deploy OTP web server to Render"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

### 3️⃣ Deploy trên Render
1. Vào https://render.com
2. Tạo "New Web Service"
3. Connect GitHub repo
4. **Render tự động tìm `render.yaml`**
5. Cấu hình env vars (xem dưới)

### 4️⃣ Environment Variables cho Render

Dán vào Render Dashboard:
```
OTP_WEB_USERS=employee1:pass1,employee2:pass2
OTP_WEB_SESSION_SIGNING_KEY=2eb1ea0144440b5c7e0595daed812ffa49d06890a4cc34eaebdd805e4d287c1
GOOGLE_SHEET_ID=1hQVKerLVOtdh4d5kk-tSo2B4Lex2hv4AmStHfnnrnio
GOOGLE_SERVICE_ACCOUNT_FILE=<Toàn bộ nội dung file JSON>
OTP_WEB_API_KEY=2546757629050b04c57ace1f98049330e98e9e7b907c38d618497bbdcf049fd7
```

**Để lấy GOOGLE_SERVICE_ACCOUNT_FILE:**
- Mở: `/Users/xz/Desktop/aaa/otp/.secrets/eastern-clock-491009-d9-210aac4760b0.json`
- Copy toàn bộ → dán vào Render

## ✅ Test local trước deploy

```bash
cd /Users/xz/Desktop/aaa/otp
bash run_otp_web.sh
```

Kiểm tra từ terminal khác:
```bash
curl http://localhost:8787/health
curl -X POST http://localhost:8787/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"employee1","password":"pass1"}'
```

## 📊 Điều gì xảy ra khi deploy?

1. Render **pull code từ GitHub**
2. Chạy `pip install -r requirements.txt`
3. Khởi động `bash run_otp_web.sh`
4. Web server **listen trên port 8787** (Render sẽ forward traffic)
5. Auto-scale nếu cần (24/7)
6. Mỗi phút kiểm tra health `/health` endpoint

## 🔗 Endpoints của Web
| Route | Mô tả |
|-------|-------|
| `GET /` | Trang chủ |
| `GET /health` | Kiểm tra sức khỏe |
| `POST /api/login` | Đăng nhập |
| `POST /api/logout` | Đăng xuất |
| `GET /api/session` | Kiểm tra phiên |
| `POST /api/getotp` | Lấy OTP |

## ⚠️ Quan trọng

- **Telegram bot vẫn chạy độc lập** (không thay đổi)
- **Web server độc lập chạy 24/7** trên Render
- **Dữ liệu chia sẻ qua Google Sheet** (cả bot + web cùng đọc)
- **Không có port conflict** - Telegram dùng polling, Web dùng HTTP
- **Thời gian hoạt động mặc định: 07:00-23:30** (có thể thay)
- **Session TTL: 30 phút** (tự động hết hạn)

## 💡 Tiếp theo sau deploy

1. Lấy URL từ Render (vd: `https://nefitly-otp-web.onrender.com`)
2. Chia cho nhân viên
3. Nhân viên login và lấy OTP qua web
4. Monitor logs: `.runtime/otp_web_access.log`

---

**Cần hỗ trợ? Xem `DEPLOY_RENDER_GUIDE.md` để chi tiết hoặc chạy `bash deploy_to_render.sh`**
