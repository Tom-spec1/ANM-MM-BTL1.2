# BTL 1.2 - Hạ tầng Khóa công khai nội bộ

Bài tập lớn môn **Mật mã và An ninh mạng (CO3017)**.

## MSSV

- 2252211
- 2213078
- 2433220
- 2410482

Root CA sử dụng Subject:

- **CN:** `CA-Root-2252211-2213078-2433220-2410482`
- **OU:** `Faculty of Computer Science and Engineer - 2252211-2213078-2433220-2410482`

## Chức năng

- Root CA nội bộ theo chuẩn X.509.
- Tiếp nhận, phê duyệt và từ chối CSR.
- Phát hành và thu hồi certificate.
- Sinh Certificate Revocation List (CRL).
- OCSP responder trả các trạng thái GOOD, REVOKED và UNKNOWN.
- Web Server chạy HTTPS/TLS bằng certificate do Root CA cấp.
- Script tái tạo dữ liệu và kiểm tra toàn bộ hệ thống.

## Yêu cầu môi trường

- Python 3.11 trở lên.
- OpenSSL có trong `PATH`.

Kiểm tra:

```powershell
python --version
openssl version
```

## Cài đặt

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Khởi tạo bộ dữ liệu PKI

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\rebuild_demo_state.py
```

Sau khi chạy, hệ thống tạo Root CA, server certificate, OCSP responder, CSR, issued certificates, CRL và cơ sở dữ liệu demo.

## Kiểm tra hệ thống

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\verify_submission.py
```

Kết quả đúng có dòng:

```text
ALL VERIFICATIONS PASSED
```

Có thể chạy từng kiểm tra:

```powershell
python .\srcs\test_ca.py
python .\srcs\test_request.py
python .\srcs\test_approve.py
python .\srcs\test_reject.py
python .\srcs\test_revoke.py
python .\srcs\test_crl.py
python .\srcs\test_ocsp_good.py
python .\srcs\test_ocsp_revoked.py
python .\srcs\test_ocsp_unknown.py
python .\srcs\test_ocsp_signature.py
```

## Chạy Web Server

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\app.py
```

Truy cập:

```text
https://127.0.0.1:5000
```

Cài Root CA vào kho tin cậy của Windows cho tài khoản hiện tại:

```powershell
certutil -addstore -user Root .\certs\rootCA.crt.pem
```

## Cấu trúc chính

```text
ANM-MM-BTL1.2/
├── README.doc
├── README.md
├── srcs/
├── refs/
├── templates/
├── database/
├── requirements.txt
└── .gitignore
```
