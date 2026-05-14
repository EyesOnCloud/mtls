import os
import ssl
import time
import logging
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger('service-b')

app = Flask(__name__)

SERVICE_NAME = os.environ.get('SERVICE_NAME', 'service-b')
TLS_ENABLED = os.environ.get('TLS_ENABLED', 'false').lower() == 'true'
MTLS_ENABLED = os.environ.get('MTLS_ENABLED', 'false').lower() == 'true'
SERVER_CERT_PATH = os.environ.get('SERVER_CERT_PATH', '/certs/service-b/service-b.crt')
SERVER_KEY_PATH = os.environ.get('SERVER_KEY_PATH', '/certs/service-b/service-b.key')
CA_CERT_PATH = os.environ.get('CA_CERT_PATH', '/certs/ca/ca.crt')

_connection_log = []

def get_tls_mode():
    if MTLS_ENABLED:
        return "mTLS (mutual TLS — both parties authenticated)"
    elif TLS_ENABLED:
        return "TLS (one-way — server only authenticated)"
    else:
        return "PLAINTEXT (no encryption, no authentication)"

def get_client_identity(req):
    """
    In a real mTLS deployment with proper TLS termination, the client
    certificate information would be available in request context or
    forwarded as headers by a proxy/gateway.

    In this lab, we inspect the environment to determine if mTLS is active
    and log accordingly. In production Nginx/Envoy setups, the client cert
    subject is forwarded as X-Client-Cert-Subject or similar.
    """
    if MTLS_ENABLED:
        cert_header = req.headers.get('X-Client-Cert-Subject', 'verified-by-tls-handshake')
        return f"Certificate verified: {cert_header}"
    return "No client certificate required or verified"

@app.route('/health')
def health():
    return jsonify({
        "service": SERVICE_NAME,
        "status": "ok",
        "tls_mode": get_tls_mode()
    }), 200

@app.route('/process', methods=['POST'])
def process():
    """
    Receives and processes requests from Service A.
    Logs connection metadata including client identity information.
    In plaintext mode, all request content is visible to any network observer.
    In mTLS mode, the connection was mutually authenticated before this code runs.
    """
    received_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body = request.get_json() or {}
    caller = body.get('from', 'unknown')
    tls_mode_received = body.get('tls_mode', 'unknown')

    client_identity = get_client_identity(request)
    remote_addr = request.remote_addr

    log_entry = {
        "received_at": received_at,
        "from_service": caller,
        "remote_addr": remote_addr,
        "tls_mode": get_tls_mode(),
        "client_identity": client_identity,
        "payload_received": body.get('payload', ''),
        "sensitive_data_in_request": body.get('sensitive_data', ''),
        "internal_token_in_request": body.get('internal_token', '')
    }

    _connection_log.append(log_entry)

    if MTLS_ENABLED:
        logger.info(f"[INBOUND] Request from {caller} ({remote_addr}) — CLIENT CERT VERIFIED")
        logger.info(f"[SECURITY] mTLS handshake completed — both identities authenticated")
    elif TLS_ENABLED:
        logger.info(f"[INBOUND] Request from {caller} ({remote_addr}) — server cert only, client NOT verified")
        logger.warning(f"[SECURITY] Client identity NOT verified — any TLS client can connect")
    else:
        logger.warning(f"[INBOUND] Request from {caller} ({remote_addr}) — PLAINTEXT — no encryption, no auth")
        logger.warning(f"[SECURITY] All request content visible to network observers")
        logger.warning(f"[SECURITY] Received sensitive data: {body.get('sensitive_data', 'none')}")

    response_payload = {
        "service": SERVICE_NAME,
        "status": "processed",
        "tls_mode": get_tls_mode(),
        "received_from": caller,
        "client_identity": client_identity,
        "processed_at": received_at,
        "internal_response": {
            "transaction_id": "TXN-2024-XK9-PROCESSED",
            "result": "APPROVED",
            "internal_routing_key": "ROUTE-EAST-CLUSTER-3",
            "database_record_id": "DB-REC-99887766"
        },
        "security_note": (
            "This response was encrypted in transit" if (TLS_ENABLED or MTLS_ENABLED)
            else "WARNING: This response was sent in PLAINTEXT — visible on the network"
        )
    }

    return jsonify(response_payload), 200

@app.route('/connection-log')
def connection_log():
    return jsonify({
        "service": SERVICE_NAME,
        "tls_mode": get_tls_mode(),
        "total_connections_received": len(_connection_log),
        "log": _connection_log[-20:]
    }), 200

@app.route('/connection-info')
def connection_info():
    return jsonify({
        "service": SERVICE_NAME,
        "tls_mode": get_tls_mode(),
        "tls_enabled": TLS_ENABLED,
        "mtls_enabled": MTLS_ENABLED,
        "server_cert": SERVER_CERT_PATH if TLS_ENABLED else "not configured",
        "ca_cert": CA_CERT_PATH if MTLS_ENABLED else "not configured",
        "client_auth": "REQUIRED" if MTLS_ENABLED else "NOT REQUIRED"
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"[STARTUP] {SERVICE_NAME} starting on port {port}")
    logger.info(f"[STARTUP] TLS mode: {get_tls_mode()}")

    if TLS_ENABLED:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)

        if MTLS_ENABLED:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations(CA_CERT_PATH)
            logger.info(f"[STARTUP] mTLS enabled — client certificates REQUIRED")
            logger.info(f"[STARTUP] Trusted CA: {CA_CERT_PATH}")
        else:
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.info(f"[STARTUP] One-way TLS — client certificates NOT required")

        app.run(host='0.0.0.0', port=port, debug=False, ssl_context=ssl_context)
    else:
        logger.warning(f"[STARTUP] TLS DISABLED — serving plaintext HTTP")
        app.run(host='0.0.0.0', port=port, debug=False)
