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
- Bộ script kiểm thử và `verify_submission.py` để xác minh chain, CRL, OCSP và trạng thái dữ liệu.

## 3. Công nghệ

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3.13 |
| Web framework | Flask 3.1.3 |
| Mật mã | `cryptography` + OpenSSL |
| Cơ sở dữ liệu | SQLite |
| Giao diện | HTML, Jinja2, Bootstrap |
| Giao thức | X.509, CRL, OCSP, HTTPS/TLS |

## 4. Cấu trúc repository

```text
ANM-MM-BTL1.2/
├── README.doc
├── README.md
├── BaoCao_BTL1_2_PKI.pdf
├── requirements.txt
├── .gitignore
├── srcs/
│   ├── app.py
│   ├── ca.py
│   ├── database.py
│   ├── ocsp.py
│   ├── project_config.py
│   ├── rebuild_demo_state.py
│   ├── verify_submission.py
│   └── test_*.py
├── templates/
│   └── *.html
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

> Các private key, database demo và certificate/CSR/CRL sinh trong lúc chạy **không được commit lên repository public**. Chúng được tạo cục bộ bằng script rebuild.

## 5. Cài đặt

### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 6. Tạo bộ dữ liệu demo

Đặt passphrase dùng để mã hóa Root CA private key trong **phiên local**:

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\rebuild_demo_state.py
```

Script tạo lại:

- Root CA và khóa riêng cục bộ;
- server certificate và OCSP responder;
- 7 CSR demo;
- 5 certificate đã cấp;
- dữ liệu gồm 5 `APPROVED`, 1 `REJECTED`, 1 `PENDING`;
- 3 certificate `REVOKED`, 2 certificate `VALID`;
- 3 phiên bản CRL;
- OCSP artifacts phục vụ kiểm thử.

## 7. Kiểm tra project

```powershell
$env:PKI_ROOT_CA_PASSPHRASE="BTL1-PKI-DEMO-LOCAL"
python .\srcs\verify_submission.py
```

Có thể chạy từng kịch bản:

```powershell
python .\srcs\test_ca.py
python .\srcs\test_approve.py
python .\srcs\test_reject.py
python .\srcs\test_revoke.py
python .\srcs\test_crl.py
python .\srcs\test_ocsp_good.py
python .\srcs\test_ocsp_revoked.py
python .\srcs\test_ocsp_unknown.py
python .\srcs\test_ocsp_signature.py
```

## 8. Khởi chạy Web

Sau khi đã rebuild demo state:

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

## 9. Trạng thái demo kỳ vọng

| Thành phần | Kết quả |
|---|---|
| CSR | 5 APPROVED, 1 REJECTED, 1 PENDING |
| Certificate | 2 VALID, 3 REVOKED |
| CRL history | 3 phiên bản |
| OCSP | GOOD / REVOKED / UNKNOWN |
| HTTPS | Certificate do Root CA nội bộ cấp |

## 10. Ghi chú bảo mật

Repository này **không lưu private key hoặc secret thực tế**. Passphrase trong ví dụ chỉ dùng để tạo khóa demo cục bộ sau khi clone; không bảo vệ bất kỳ khóa nào được commit lên GitHub.

Báo cáo kỹ thuật được nộp kèm trong gói Assignment1 của nhóm.
