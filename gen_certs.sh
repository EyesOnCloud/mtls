#!/bin/bash

# ─────────────────────────────────────────────────────────────────────────────
# gen_certs.sh — Generate a complete PKI for the mTLS
#
# Creates:
#   certs/ca/             — Root Certificate Authority
#   certs/service-a/      — Client certificate for Service A
#   certs/service-b/      — Server (and client) certificate for Service B
#
# All certificates use 2048-bit RSA keys and SHA-256 signatures.
# Validity: 365 days — appropriate for a lab environment.
# In production, internal service certificates should rotate every 90 days
# or less, ideally via an automated certificate management system.
# ─────────────────────────────────────────────────────────────────────────────

set -e

CERT_DIR="./certs"
CA_DIR="${CERT_DIR}/ca"
SERVICE_A_DIR="${CERT_DIR}/service-a"
SERVICE_B_DIR="${CERT_DIR}/service-b"
ROGUE_DIR="${CERT_DIR}/rogue-service"

echo ""
echo "════════════════════════════════════════════════════════"
echo " Generating PKI for mTLS Lab"
echo "════════════════════════════════════════════════════════"

# ── Clean and create directory structure ──────────────────────────────────────
rm -rf "$CERT_DIR"
mkdir -p "$CA_DIR" "$SERVICE_A_DIR" "$SERVICE_B_DIR" "$ROGUE_DIR"

echo ""
echo "[STEP 1] Generating Root Certificate Authority..."
echo "─────────────────────────────────────────────────"
echo "The CA is the trust anchor. Both services will be configured"
echo "to trust certificates issued by this CA and ONLY this CA."
echo "This is the 'who do you trust' declaration in mTLS."
echo ""

# Generate CA private key (4096-bit for the CA — CAs use stronger keys)
openssl genrsa -out "${CA_DIR}/ca.key" 4096
echo "CA private key generated (4096-bit RSA)"

# Generate self-signed CA certificate
openssl req -new -x509 \
    -key "${CA_DIR}/ca.key" \
    -out "${CA_DIR}/ca.crt" \
    -days 365 \
    -subj "/C=US/O=LabInternalCA/CN=Lab-Root-CA/OU=SecurityLab" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "CA certificate generated (self-signed, 365 days)"
echo ""
echo "    CA Subject  : $(openssl x509 -in ${CA_DIR}/ca.crt -noout -subject)"
echo "    CA Issuer   : $(openssl x509 -in ${CA_DIR}/ca.crt -noout -issuer)"
echo "    Valid until : $(openssl x509 -in ${CA_DIR}/ca.crt -noout -enddate)"

echo ""
echo "[STEP 2] Generating Service B Certificate (Server Identity)..."
echo "─────────────────────────────────────────────────────────────"
echo "Service B acts as the server. Its certificate proves to connecting"
echo "clients that they are talking to the real Service B, not an impersonator."
echo "The SAN (Subject Alternative Name) must match the hostname Service A uses."
echo ""

# Generate Service B private key
openssl genrsa -out "${SERVICE_B_DIR}/service-b.key" 2048
echo "Service B private key generated (2048-bit RSA)"

# Generate Service B CSR (Certificate Signing Request)
openssl req -new \
    -key "${SERVICE_B_DIR}/service-b.key" \
    -out "${SERVICE_B_DIR}/service-b.csr" \
    -subj "/C=US/O=LabServices/CN=service-b/OU=Backend"

echo "Service B CSR generated"

# Create extension file for Service B certificate
cat > /tmp/service-b-ext.cnf << 'EOF'
[v3_server]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=service-b
DNS.2=localhost
DNS.3=service-b.lab-mtls-network
IP.1=127.0.0.1
EOF

# Sign Service B certificate with the CA
openssl x509 -req \
    -in "${SERVICE_B_DIR}/service-b.csr" \
    -CA "${CA_DIR}/ca.crt" \
    -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${SERVICE_B_DIR}/service-b.crt" \
    -days 365 \
    -extfile /tmp/service-b-ext.cnf \
    -extensions v3_server

echo "Service B certificate signed by CA (365 days)"
echo ""
echo "    Subject  : $(openssl x509 -in ${SERVICE_B_DIR}/service-b.crt -noout -subject)"
echo "    SANs     : $(openssl x509 -in ${SERVICE_B_DIR}/service-b.crt -noout -ext subjectAltName 2>/dev/null | tail -1)"
echo "    Valid until: $(openssl x509 -in ${SERVICE_B_DIR}/service-b.crt -noout -enddate)"

echo ""
echo "[STEP 3] Generating Service A Certificate (Client Identity)..."
echo "──────────────────────────────────────────────────────────────"
echo "Service A acts as the client in mTLS. Its certificate proves to"
echo "Service B that the caller is the authorized Service A, not an"
echo "unauthorized service or attacker posing as Service A."
echo ""

# Generate Service A private key
openssl genrsa -out "${SERVICE_A_DIR}/service-a.key" 2048
echo "[✓] Service A private key generated (2048-bit RSA)"

# Generate Service A CSR
openssl req -new \
    -key "${SERVICE_A_DIR}/service-a.key" \
    -out "${SERVICE_A_DIR}/service-a.csr" \
    -subj "/C=US/O=LabServices/CN=service-a/OU=Frontend"

echo "Service A CSR generated"

# Create extension file for Service A certificate
cat > /tmp/service-a-ext.cnf << 'EOF'
[v3_client]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=service-a
DNS.2=localhost
IP.1=127.0.0.1
EOF

# Sign Service A certificate with the CA
openssl x509 -req \
    -in "${SERVICE_A_DIR}/service-a.csr" \
    -CA "${CA_DIR}/ca.crt" \
    -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${SERVICE_A_DIR}/service-a.crt" \
    -days 365 \
    -extfile /tmp/service-a-ext.cnf \
    -extensions v3_client

echo "Service A certificate signed by CA (365 days)"
echo ""
echo "    Subject  : $(openssl x509 -in ${SERVICE_A_DIR}/service-a.crt -noout -subject)"
echo "    Valid until: $(openssl x509 -in ${SERVICE_A_DIR}/service-a.crt -noout -enddate)"

echo ""
echo "[STEP 4] Generating Rogue Service Certificate (Different CA)..."
echo "──────────────────────────────────────────────────────────────"
echo "This simulates an unauthorized service that generates its own"
echo "self-signed certificate or uses a different CA. Service B will"
echo "reject connections from this certificate because it is not signed"
echo "by the trusted Lab CA. This is the core of mTLS identity enforcement."
echo ""

# Rogue CA (different CA — not trusted by our services)
openssl genrsa -out "${ROGUE_DIR}/rogue-ca.key" 2048
openssl req -new -x509 \
    -key "${ROGUE_DIR}/rogue-ca.key" \
    -out "${ROGUE_DIR}/rogue-ca.crt" \
    -days 365 \
    -subj "/C=XX/O=RogueOrg/CN=Rogue-CA"

# Rogue service certificate signed by the rogue CA
openssl genrsa -out "${ROGUE_DIR}/rogue.key" 2048
openssl req -new \
    -key "${ROGUE_DIR}/rogue.key" \
    -out "${ROGUE_DIR}/rogue.csr" \
    -subj "/C=XX/O=RogueOrg/CN=rogue-service"
openssl x509 -req \
    -in "${ROGUE_DIR}/rogue.csr" \
    -CA "${ROGUE_DIR}/rogue-ca.crt" \
    -CAkey "${ROGUE_DIR}/rogue-ca.key" \
    -CAcreateserial \
    -out "${ROGUE_DIR}/rogue.crt" \
    -days 365

echo "Rogue service certificate generated (signed by untrusted CA)"

echo ""
echo "[STEP 5] Verifying certificate chain..."
echo "────────────────────────────────────────"

echo -n "Service B cert verified against CA: "
openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVICE_B_DIR}/service-b.crt" 2>&1

echo -n "Service A cert verified against CA: "
openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVICE_A_DIR}/service-a.crt" 2>&1

echo -n "Rogue cert verified against lab CA (should FAIL): "
openssl verify -CAfile "${CA_DIR}/ca.crt" "${ROGUE_DIR}/rogue.crt" 2>&1 || echo "(Expected failure — rogue cert NOT trusted by lab CA)"

# ── Set correct permissions ───────────────────────────────────────────────────
chmod 600 "${CA_DIR}/ca.key"
chmod 600 "${SERVICE_A_DIR}/service-a.key"
chmod 600 "${SERVICE_B_DIR}/service-b.key"
chmod 600 "${ROGUE_DIR}/rogue.key"
chmod 644 "${CA_DIR}/ca.crt"
chmod 644 "${SERVICE_A_DIR}/service-a.crt"
chmod 644 "${SERVICE_B_DIR}/service-b.crt"

echo ""
echo "════════════════════════════════════════════════════════"
echo " Certificate Generation Complete"
echo "════════════════════════════════════════════════════════"
echo ""
echo " Directory structure:"
find "$CERT_DIR" -type f | sort | while read f; do
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
    echo "  $f (${SIZE} bytes)"
done
echo ""
echo " Trust relationships:"
echo "  Lab CA → signs → service-b.crt (trusted by Service A and Service B)"
echo "  Lab CA → signs → service-a.crt (trusted by Service A and Service B)"
echo "  Rogue CA → signs → rogue.crt (NOT trusted by Service A or Service B)"
echo "════════════════════════════════════════════════════════"
