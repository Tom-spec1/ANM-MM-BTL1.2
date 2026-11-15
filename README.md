# Internal PKI - BTL 1.2 | Mật mã và An ninh mạng

Hệ thống **Public Key Infrastructure (PKI) nội bộ** cho Bài tập lớn số 1 - phần 1.2. Project hiện thực Root Certificate Authority (CA), tiếp nhận và xử lý CSR, phát hành/thu hồi chứng thư X.509, CRL, OCSP và Web Server chạy HTTPS/TLS.

## 1. Thành viên

- 2252211
- 2213078
- 2433220
- 2410482

Root CA được cá thể hóa theo yêu cầu đề bài:

- **CN:** `CA-Root-2252211-2213078-2433220-2410482`
- **OU:** `Faculty of Computer Science and Engineer - 2252211-2213078-2433220-2410482`

## 2. Chức năng chính

- Root CA tự ký, RSA 4096-bit, `CA:TRUE`, có quyền `Certificate Sign` và `CRL Sign`.
- Tiếp nhận CSR và quản lý vòng đời `PENDING / APPROVED / REJECTED`.
- Phát hành chứng thư X.509 cho request hợp lệ.
- Quản lý chứng thư `VALID / REVOKED`, lưu thời điểm và lý do thu hồi.
- Sinh X.509 CRL có chữ ký Root CA và lưu lịch sử CRL.
- OCSP responder riêng, trả `GOOD / REVOKED / UNKNOWN` và ký response bằng certificate có EKU `OCSP Signing`.
- Web Server chạy HTTPS/TLS bằng certificate do Root CA nội bộ cấp, SAN `localhost` và `127.0.0.1`.
- Có script rebuild toàn bộ demo state và verifier không phá dữ liệu.

## 3. Công nghệ

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python |
| Web framework | Flask 3.1.3 |
| Mật mã | `cryptography` + OpenSSL |
| Cơ sở dữ liệu | SQLite |
| Giao diện | HTML, Jinja2, Bootstrap |
| Giao thức | X.509, CRL, OCSP, HTTPS/TLS |

## 4. Cấu trúc repository public

```text
ANM-MM-BTL1.2/
├── README.md
├── requirements.txt
├── .gitignore
├── srcs/
│   ├── app.py
│   ├── ca.py
│   ├── database.py
│   ├── ocsp.py
│   ├── project_config.py
│   ├── rebuild_demo_state.py
│   └── verify_submission.py
├── templates/
│   ├── index.html
│   ├── requests.html
│   ├── request_details.html
│   ├── certificates.html
│   ├── certificate_details.html
│   └── crl.html
├── database/
│   └── schema.sql
└── refs/
    ├── DANH_MUC_TAI_LIEU_THAM_KHAO.md
    ├── libraries/
    │   └── THU_VIEN_MA_NGUON_MO.md
    └── rfcs/
        ├── RFC5280_X509_PKI.md
        └── RFC6960_OCSP.md
```

> Repository public không commit private key, database demo, certificate/CSR/CRL sinh trong lúc chạy. Các file này được tạo cục bộ bằng script rebuild. Báo cáo kỹ thuật và bộ artefact demo đầy đủ nằm trong gói `Assignment1.zip` nộp cho giảng viên.

## 5. Yêu cầu môi trường

- Python 3.11+.
- OpenSSL có trong `PATH`.

Kiểm tra:

```powershell
python --version
openssl version
```

## 6. Cài đặt

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 7. Tạo bộ dữ liệu demo

Đặt passphrase demo cho Root CA trong phiên local:

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\rebuild_demo_state.py
```

Script sẽ tạo Root CA, server certificate, OCSP responder, 7 CSR demo, 5 certificate đã cấp, 3 phiên bản CRL và các artefact OCSP.

Trạng thái kỳ vọng:

| Thành phần | Kết quả |
|---|---|
| CSR | 5 APPROVED, 1 REJECTED, 1 PENDING |
| Certificate | 2 VALID, 3 REVOKED |
| CRL history | 3 phiên bản |
| OCSP | GOOD / REVOKED / UNKNOWN |
| HTTPS | Certificate do Root CA nội bộ cấp |

## 8. Kiểm tra project

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\verify_submission.py
```

Kết quả đúng sẽ có dòng:

```text
ALL VERIFICATIONS PASSED
```

## 9. Khởi chạy Web

Sau khi rebuild:

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\app.py
```

Truy cập:

```text
https://127.0.0.1:5000
```

Nếu muốn Windows tin Root CA demo:

```powershell
certutil -addstore -user Root .\certs\rootCA.crt.pem
```

## 10. Ghi chú bảo mật

Repository này không lưu private key hoặc secret thực tế. Passphrase ví dụ chỉ dùng để sinh khóa demo cục bộ sau khi clone.
