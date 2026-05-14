import os
import ssl
import time
import logging
import requests
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger('service-a')

app = Flask(__name__)

SERVICE_NAME = os.environ.get('SERVICE_NAME', 'service-a')
SERVICE_B_URL = os.environ.get('SERVICE_B_URL', 'http://service-b:8080')
TLS_ENABLED = os.environ.get('TLS_ENABLED', 'false').lower() == 'true'
MTLS_ENABLED = os.environ.get('MTLS_ENABLED', 'false').lower() == 'true'
CA_CERT_PATH = os.environ.get('CA_CERT_PATH', '/certs/ca/ca.crt')
CLIENT_CERT_PATH = os.environ.get('CLIENT_CERT_PATH', '/certs/service-a/service-a.crt')
CLIENT_KEY_PATH = os.environ.get('CLIENT_KEY_PATH', '/certs/service-a/service-a.key')

def get_tls_mode():
    if MTLS_ENABLED:
        return "mTLS (mutual TLS — both parties authenticated)"
    elif TLS_ENABLED:
        return "TLS (one-way — server only authenticated)"
    else:
        return "PLAINTEXT (no encryption, no authentication)"

def call_service_b(payload):
    """
    Makes an outbound HTTP or HTTPS call to Service B.
    The TLS configuration is controlled entirely by environment variables —
    the same application code handles all three phases of the lab.

    Phase 1 (no TLS): Plain HTTP with requests.get — no SSL configuration
    Phase 2 (one-way TLS): HTTPS with CA cert for server verification
    Phase 3 (mTLS): HTTPS with CA cert + client cert + client key
    """
    start_time = time.time()
    target_url = f"{SERVICE_B_URL}/process"

    connection_metadata = {
        "from": SERVICE_NAME,
        "to": "service-b",
        "target_url": target_url,
        "tls_mode": get_tls_mode(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    logger.info(f"[OUTBOUND] Calling Service B at {target_url}")
    logger.info(f"[OUTBOUND] TLS mode: {get_tls_mode()}")

    try:
        if not TLS_ENABLED:
            logger.warning("[SECURITY] Sending request over PLAINTEXT — traffic is unencrypted and unverified")
            response = requests.post(
                target_url,
                json={
                    "from": SERVICE_NAME,
                    "payload": payload,
                    "sensitive_data": "CUSTOMER_RECORD:id=12345,ssn=123-45-6789,card=4532015112830366",
                    "internal_token": "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXNlcnZpY2UtdG9rZW4.example",
                    "tls_mode": "plaintext"
                },
                timeout=5
            )

        elif TLS_ENABLED and not MTLS_ENABLED:
            logger.info("[SECURITY] Sending request over TLS — server identity verified, client identity NOT verified")
            response = requests.post(
                target_url,
                json={
                    "from": SERVICE_NAME,
                    "payload": payload,
                    "sensitive_data": "CUSTOMER_RECORD:id=12345,ssn=123-45-6789,card=4532015112830366",
                    "internal_token": "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXNlcnZpY2UtdG9rZW4.example",
                    "tls_mode": "tls-one-way"
                },
                verify=CA_CERT_PATH,
                timeout=5
            )

        else:
            logger.info("[SECURITY] Sending request over mTLS — both service identities verified")
            response = requests.post(
                target_url,
                json={
                    "from": SERVICE_NAME,
                    "payload": payload,
                    "sensitive_data": "CUSTOMER_RECORD:id=12345,ssn=123-45-6789,card=4532015112830366",
                    "internal_token": "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXNlcnZpY2UtdG9rZW4.example",
                    "tls_mode": "mtls"
                },
                verify=CA_CERT_PATH,
                cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
                timeout=5
            )

        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"[OUTBOUND] Service B responded: HTTP {response.status_code} in {elapsed}ms")

        return {
            "status": "success",
            "connection_metadata": connection_metadata,
            "service_b_response": response.json(),
            "response_time_ms": elapsed
        }, 200

    except requests.exceptions.SSLError as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"[TLS ERROR] SSL/TLS handshake failed: {e}")
        return {
            "status": "tls_error",
            "error": str(e),
            "connection_metadata": connection_metadata,
            "explanation": "TLS handshake failed — certificate verification error or mutual auth required",
            "response_time_ms": elapsed
        }, 502

    except requests.exceptions.ConnectionError as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"[CONNECTION ERROR] Cannot reach Service B: {e}")
        return {
            "status": "connection_error",
            "error": str(e),
            "connection_metadata": connection_metadata,
            "response_time_ms": elapsed
        }, 502

    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"[ERROR] Unexpected error: {type(e).__name__}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "response_time_ms": elapsed
        }, 500

@app.route('/health')
def health():
    return jsonify({
        "service": SERVICE_NAME,
        "status": "ok",
        "tls_mode": get_tls_mode(),
        "service_b_url": SERVICE_B_URL
    }), 200

@app.route('/call-service-b', methods=['GET', 'POST'])
def trigger_call():
    """
    Triggers Service A to call Service B.
    This is the endpoint the lab uses to generate traffic for tcpdump capture.
    """
    body = request.get_json() or {}
    payload = body.get('payload', 'default-test-payload')

    logger.info(f"[REQUEST] Received call-service-b request. Payload: {payload}")
    result, status_code = call_service_b(payload)
    return jsonify(result), status_code

@app.route('/connection-info')
def connection_info():
    return jsonify({
        "service": SERVICE_NAME,
        "tls_mode": get_tls_mode(),
        "tls_enabled": TLS_ENABLED,
        "mtls_enabled": MTLS_ENABLED,
        "service_b_url": SERVICE_B_URL,
        "ca_cert_path": CA_CERT_PATH if TLS_ENABLED else "not used",
        "client_cert_path": CLIENT_CERT_PATH if MTLS_ENABLED else "not used",
        "security_warning": "none" if (TLS_ENABLED or MTLS_ENABLED) else "TRAFFIC IS UNENCRYPTED"
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"[STARTUP] {SERVICE_NAME} starting on port {port}")
    logger.info(f"[STARTUP] TLS mode: {get_tls_mode()}")
    app.run(host='0.0.0.0', port=port, debug=False)
