#!/bin/bash
# Generate throwaway mTLS certificates for development.
#
# Usage: mkcerts.sh [AGENT_CN]
#
# Each host MUST have its own agent certificate with a UNIQUE common name (CN).
# The control plane binds a volume to the enrolling client's CN and refuses to
# release a key to any other identity, so a shared agent CN would let every host
# unlock every other host's volume. AGENT_CN defaults to this machine's
# hostname; pass an explicit value to mint a cert for a specific host.

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

AGENT_CN="${1:-$(hostname -f 2>/dev/null || hostname)}"
echo "Issuing agent certificate with CN=${AGENT_CN}"

# Generate CA private key
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# Generate CA certificate
openssl req -new -x509 -key "$CERT_DIR/ca.key" -sha256 -subj "/C=US/ST=CA/O=Cryptor Dev/CN=Cryptor Dev CA" -days 3650 -out "$CERT_DIR/ca.crt"

# Generate server private key
openssl genrsa -out "$CERT_DIR/server.key" 4096

# Generate server certificate signing request
openssl req -subj "/C=US/ST=CA/O=Cryptor Dev/CN=rootseal-server" -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr"

# Generate server certificate
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 -sha256 -extfile <(
cat <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1=rootseal-server
DNS.2=localhost
IP.1=127.0.0.1
IP.2=::1
EOF
)

# Generate agent private key
openssl genrsa -out "$CERT_DIR/agent.key" 4096

# Generate agent certificate signing request (per-host unique CN)
openssl req -subj "/C=US/ST=CA/O=Cryptor Dev/CN=${AGENT_CN}" -new -key "$CERT_DIR/agent.key" -out "$CERT_DIR/agent.csr"

# Generate agent certificate
openssl x509 -req -in "$CERT_DIR/agent.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/agent.crt" -days 365 -sha256

# Generate init private key
openssl genrsa -out "$CERT_DIR/init.key" 4096

# Generate init certificate signing request
openssl req -subj "/C=US/ST=CA/O=Cryptor Dev/CN=rootseal-init" -new -key "$CERT_DIR/init.key" -out "$CERT_DIR/init.csr"

# Generate init certificate
openssl x509 -req -in "$CERT_DIR/init.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/init.crt" -days 365 -sha256

# Clean up CSRs
rm "$CERT_DIR"/*.csr

# Set appropriate permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "Generated development certificates in $CERT_DIR/"
echo "CA: $CERT_DIR/ca.crt"
echo "Server: $CERT_DIR/server.{crt,key}"
echo "Agent: $CERT_DIR/agent.{crt,key} (CN=${AGENT_CN})"
echo "Init: $CERT_DIR/init.{crt,key}"
echo
echo "NOTE: re-run with a per-host CN for each additional host, e.g.:"
echo "  $0 host01.example.com"
