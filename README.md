# GỬI VC AN TOÀN VÀ KIỂM TRA IP


  Hệ thống "Gửi CV An Toàn và Xác Thực IP" là một ứng dụng được xây dựng bằng Python nhằm đảm bảo tính bảo mật, tính toàn vẹn và tính xác thực khi truyền tải file CV (dạng PDF) giữa hai máy tính qua mạng. Hệ thống sử dụng các kỹ thuật mã hóa hiện đại như AES (Advanced Encryption Standard) để mã hóa nội dung file và RSA để mã hóa khóa phiên AES. Đồng thời, hệ thống còn tích hợp chữ ký số bằng thuật toán SHA512 kết hợp PKCS1_v1.5 để xác minh nguồn gốc và đảm bảo rằng dữ liệu không bị thay đổi trong quá trình truyền.

  Một điểm quan trọng của hệ thống là chức năng kiểm tra địa chỉ IP của máy gửi trước khi chấp nhận kết nối, nhằm ngăn chặn việc nhận file từ các nguồn không đáng tin cậy. Việc truyền file được thực hiện qua giao thức TCP socket, cho phép kết nối trực tiếp trong mạng nội bộ (LAN) giữa hai máy tính: một máy gửi file và một máy nhận file.

Hệ thống hoạt động qua giao diện dòng lệnh đơn giản, dễ triển khai, với quy trình gồm: xác thực IP, trao đổi khóa công khai RSA, ký và kiểm tra chữ ký số, mã hóa và giải mã file. Kết quả cuối cùng là file CV gốc sẽ được truyền và lưu lại chính xác ở phía người nhận nếu mọi bước xác thực đều thành công.

---

## 📌 Giới thiệu

**Gửi CV An Toàn và Xác Thực IP** là một ứng dụng Python giúp gửi file PDF (CV) giữa hai máy tính trong cùng mạng một cách **an toàn** và **đáng tin cậy**.

Hệ thống đảm bảo:
- 🔐 Mã hóa file bằng **AES-CBC**
- 🔑 Bảo vệ khóa AES bằng **RSA 1024-bit + OAEP**
- ✍️ Ký số metadata bằng **PKCS1_v1.5 + SHA512**
- 🛡️ Xác thực địa chỉ IP người gửi
- 🧾 Kiểm tra toàn vẹn file bằng **SHA-512**

> File chỉ được chấp nhận nếu đúng IP, đúng chữ ký số, và dữ liệu không bị thay đổi.

---

## 🗂️ Cấu trúc dự án

      project/
      |-- crypto_utils.py       : Mã hóa AES/RSA, ký số, hash
      |-- protocol.py           : Gói/giải gói dữ liệu JSON
      |-- sender.py             : Người gửi: mã hóa và gửi file
      |-- receiver.py           : Người nhận: xác thực và giải mã
      |-- cv.pdf                : File gốc cần gửi
      |-- cv_received.pdf       : File sau khi giải mã


less
Sao chép
Chỉnh sửa

---

## 🛠️ Công nghệ sử dụng

| Thành phần      | Công nghệ                         |
|------------------|-----------------------------------|
| Ngôn ngữ lập trình | Python 3.10+                    |
| Mã hóa dữ liệu   | AES-CBC (`cryptography`)          |
| Trao đổi khóa    | RSA 1024-bit + OAEP               |
| Ký số & hash     | SHA512 + PKCS1v15                 |
| Giao tiếp mạng   | TCP socket                        |
| Định dạng gói tin| JSON + Base64                     |

> 🔧 Cài thư viện cần thiết:

        pip install cryptography

🚀 Hướng dẫn chạy chương trình

1️⃣ Cấu hình IP

- Mở receiver.py: thêm IP máy gửi vào biến whitelist.
- Mở sender.py: sửa host thành IP của máy nhận.
- Nếu dùng cùng một máy, giữ nguyên 127.0.0.1.

2️⃣ Chạy máy nhận (Receiver)
- bash
- Sao chép
- Chỉnh sửa
     ```bash
      python receiver.py
- Mở cổng socket, chờ kết nối từ máy gửi.
- Gửi khóa công khai RSA cho máy gửi.

3️⃣ Chạy máy gửi (Sender)
- bash
- Sao chép
- Chỉnh sửa
    ```bash
    python sender.py
- Gửi handshake xác thực IP.
- Nhận public key từ máy nhận.
- Gửi public key của mình.
- Mã hóa file cv.pdf, ký metadata, gói và gửi đi.

---
## 🔄 Quy trình bảo mật
- 🤝 Handshake: Hello|IP và kiểm tra IP whitelist
- 🔑 Trao đổi khóa công khai RSA
- ✍️ Ký metadata: filename | timestamp | sender_ip
- 🔐 Mã hóa file bằng AES-CBC
- 📦 Mã hóa khóa AES bằng RSA và đóng gói
- ✅ Người nhận kiểm tra hash, chữ ký và IP
- 📁 Giải mã file, lưu thành cv_received.pdf

---
## 🧪 Kiểm thử
| 🧪 **Tình huống**                | 💬 **Phản hồi từ hệ thống**            |
| -------------------------------- | -------------------------------------- |
| ✅ IP đúng, dữ liệu hợp lệ        | `ACK` – Lưu tệp thành công             |
| ❌ IP không hợp lệ                | `NACK (IP)` – Từ chối kết nối          |
| ❌ Metadata bị giả mạo            | `NACK (auth)` – Sai chữ ký số          |
| ❌ Ciphertext hoặc IV bị thay đổi | `NACK (integrity)` – Sai hash toàn vẹn |

---
## 🤝 Đóng góp
Dự án được thực hiện bởi Nhóm 9 – Lớp CNTT17-11 – Trường Đại học Đại Nam:
| 👤 **Họ và Tên**        | 🎯 **Vai trò**                                                               |
| ----------------------- | ---------------------------------------------------------------------------- |
| **Phạm Văn Trà**        | Phát triển mã nguồn, thiết kế kiến trúc hệ thống, kiểm thử và viết tài liệu. |
| **Phạm Thị Ngọc Thanh** | Biên soạn tài liệu, đề xuất cải tiến và hỗ trợ xử lý bài tập lớn.            |
| **Đinh Mai Phương**     | Phát triển mã nguồn, kiểm thử, triển khai dự án và hỗ trợ demo.              |

