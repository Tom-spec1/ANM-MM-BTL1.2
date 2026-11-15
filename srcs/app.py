from pathlib import Path

from flask import (
    Flask, request, Response, render_template,
    abort, redirect, url_for, send_file
)

from cryptography import x509
from cryptography.x509 import ocsp as cryptography_ocsp
from cryptography.hazmat.primitives.serialization import Encoding

from database import get_connection
from ca import (
    approve_request,
    reject_request,
    revoke_certificate,
    generate_crl
)
from ocsp import create_ocsp_response

app = Flask(__name__, template_folder="../templates")
BASE_DIR = Path(__file__).resolve().parent.parent


@app.route("/")
def home():
    connection = get_connection()

    try:
        # Tổng số yêu cầu cấp chứng thư
        total_requests = connection.execute(
            "SELECT COUNT(*) FROM certificate_requests"
        ).fetchone()[0]

        # Tổng số chứng thư hợp lệ
        valid_certificates = connection.execute(
            "SELECT COUNT(*) FROM certificates WHERE status = 'VALID'"
        ).fetchone()[0]

        # Tổng số chứng thư đã thu hồi
        revoked_certificates = connection.execute(
            "SELECT COUNT(*) FROM certificates WHERE status = 'REVOKED'"
        ).fetchone()[0]

        # Tổng số yêu cầu đang chờ xử lý
        pending_requests = connection.execute(
            "SELECT COUNT(*) FROM certificate_requests WHERE status = 'PENDING'"
        ).fetchone()[0]

    finally:
        connection.close()

    return render_template(
        "index.html",
        total_requests=total_requests,
        valid_certificates=valid_certificates,
        revoked_certificates=revoked_certificates,
        pending_requests=pending_requests
    )

@app.route("/requests")
def certificate_requests():
    connection = get_connection()

    try:
        requests = connection.execute("""
            SELECT
                request_id,
                common_name,
                subject,
                status,
                submitted_at,
                processed_at,
                rejection_reason
            FROM certificate_requests
            ORDER BY request_id ASC
        """).fetchall()

    finally:
        connection.close()

    return render_template(
        "requests.html",
        requests=requests
    )

@app.route("/requests/<int:request_id>")
def request_details(request_id):
    connection = get_connection()

    try:
        certificate_request = connection.execute("""
            SELECT *
            FROM certificate_requests
            WHERE request_id = ?
        """, (request_id,)).fetchone()

    finally:
        connection.close()

    if certificate_request is None:
        abort(404)

    return render_template(
        "request_details.html",
        certificate_request=certificate_request
    )



@app.route("/requests/<int:request_id>/approve", methods=["POST"])
def approve_certificate_request(request_id):
    extension_path = BASE_DIR / "requests" / "request_ext.cnf"

    output_path = (
        BASE_DIR / "certs" / "request"
        / f"request_{request_id}.crt.pem"
    )

    try:
        approve_request(
            request_id,
            str(extension_path),
            str(output_path)
        )

        return redirect(url_for(
            "request_details",
            request_id=request_id,
            message="approve_success"
        ))

    except Exception:
        app.logger.exception("Certificate approval failed")

        return redirect(url_for(
            "request_details",
            request_id=request_id,
            message="approve_error"
        ))
        
        
@app.route("/requests/<int:request_id>/reject", methods=["POST"])
def reject_certificate_request(request_id):
    reason = request.form.get("reason", "").strip()

    if not reason:
        return redirect(url_for(
            "request_details",
            request_id=request_id,
            message="missing_reason"
        ))

    try:
        reject_request(request_id, reason)

        return redirect(url_for(
            "request_details",
            request_id=request_id,
            message="reject_success"
        ))

    except Exception:
        app.logger.exception("Certificate rejection failed")

        return redirect(url_for(
            "request_details",
            request_id=request_id,
            message="reject_error"
        ))

@app.route("/certificates")
def certificate_list():
    connection = get_connection()

    try:
        certificates = connection.execute("""
           
SELECT
    serial_number,
    subject,
    issuer,
    not_before,
    not_after,
    status,
    issued_at,
    revoked_at,
    revocation_reason
FROM certificates
WHERE status = 'VALID'
ORDER BY issued_at ASC

        """).fetchall()

    finally:
        connection.close()

    return render_template(
    "certificates.html",
    certificates=certificates,
    page_title="Valid Certificates"
)



@app.route("/certificates/revoked")
def revoked_certificate_list():
    connection = get_connection()

    try:
        certificates = connection.execute("""
            SELECT
                serial_number,
                subject,
                issuer,
                not_before,
                not_after,
                status,
                issued_at,
                revoked_at,
                revocation_reason
            FROM certificates
            WHERE status = 'REVOKED'
            ORDER BY revoked_at DESC
        """).fetchall()

    finally:
        connection.close()

    return render_template(
    "certificates.html",
    certificates=certificates,
    page_title="Revoked Certificates"
)





@app.route("/certificates/<serial_number>")
def certificate_details(serial_number):
    connection = get_connection()

    try:
        certificate_record = connection.execute("""
            SELECT *
            FROM certificates
            WHERE serial_number = ?
        """, (serial_number,)).fetchone()

    finally:
        connection.close()

    if certificate_record is None:
        abort(404)

    certificate = x509.load_pem_x509_certificate(
        certificate_record["certificate_pem"].encode("utf-8")
    )

    return render_template(
        "certificate_details.html",
        certificate_record=certificate_record,
        certificate=certificate
    )





@app.route("/ocsp", methods=["POST"])
def ocsp_endpoint():
    # Nhan OCSP Request dang DER
    request_data = request.get_data()

    # Phan tich OCSP Request
    try:
        ocsp_request = cryptography_ocsp.load_der_ocsp_request(
            request_data
        )
    except ValueError:
        return Response(
            "Invalid OCSP Request",
            status=400,
            mimetype="text/plain"
        )

    # Tao OCSP Response
    try:
        ocsp_response = create_ocsp_response(ocsp_request)

        response_data = ocsp_response.public_bytes(
            Encoding.DER
        )

        return Response(
            response_data,
            status=200,
            mimetype="application/ocsp-response"
        )

    except Exception:
        app.logger.exception("OCSP response generation failed")
        return Response(
            "OCSP response generation failed",
            status=500,
            mimetype="text/plain"
        )



@app.route("/certificates/<serial_number>/revoke", methods=["POST"])
def revoke_certificate_route(serial_number):
    reason = request.form.get("reason", "").strip()

    if not reason:
        return redirect(
            url_for(
                "certificate_details",
                serial_number=serial_number,
                message="missing_reason"
            )
        )

    # Buoc 1: Thu hoi chung thu trong SQLite
    try:
        revoke_certificate(serial_number, reason)

    except Exception:
        app.logger.exception("Certificate revocation failed")

        return redirect(
            url_for(
                "certificate_details",
                serial_number=serial_number,
                message="revoke_error"
            )
        )

    # Buoc 2: Tao CRL moi
    try:
        generate_crl()

    except Exception:
        app.logger.exception("CRL generation failed")

        return redirect(
            url_for(
                "certificate_details",
                serial_number=serial_number,
                message="crl_error"
            )
        )

    # Ca hai buoc deu thanh cong
    return redirect(
        url_for(
            "certificate_details",
            serial_number=serial_number,
            message="revoke_success"
        )
    )


@app.route("/crl")
def crl_management():
    connection = get_connection()

    try:
        # Get CRL history in ascending order
        crl_records = connection.execute("""
            SELECT
                crl_number,
                this_update,
                next_update,
                created_at,
                crl_pem
            FROM crl_records
            ORDER BY crl_number ASC
        """).fetchall()

        # Get the latest CRL
        current_crl = connection.execute("""
            SELECT
                crl_number,
                this_update,
                next_update,
                created_at,
                crl_pem
            FROM crl_records
            ORDER BY crl_number DESC
            LIMIT 1
        """).fetchone()

    finally:
        connection.close()

    revoked_count = 0

    if current_crl:
        crl = x509.load_pem_x509_crl(
            current_crl["crl_pem"].encode("utf-8")
        )
        revoked_count = len(crl)

    return render_template(
        "crl.html",
        crl_records=crl_records,
        current_crl=current_crl,
        revoked_count=revoked_count
    )
    
    
    
@app.route("/crl/download")
def download_crl():
    crl_path = BASE_DIR / "certs" / "crl" / "rootCA.crl.pem"

    if not crl_path.exists():
        abort(404)

    return send_file(
        crl_path,
        as_attachment=True,
        download_name="rootCA.crl.pem",
        mimetype="application/pkix-crl"
    )



if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=(
            "certs/server.crt.pem",
            "private/server/server.key.pem"
        ),
        debug=False
    )
