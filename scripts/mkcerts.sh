#!/bin/bash
# Generate throwaway mTLS certificates for development

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

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

# Generate agent certificate signing request
openssl req -subj "/C=US/ST=CA/O=Cryptor Dev/CN=rootseal" -new -key "$CERT_DIR/agent.key" -out "$CERT_DIR/agent.csr"

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
echo "Agent: $CERT_DIR/agent.{crt,key}"
echo "Init: $CERT_DIR/init.{crt,key}"
