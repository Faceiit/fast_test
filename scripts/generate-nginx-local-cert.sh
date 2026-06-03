#!/usr/bin/env bash

# scripts/generate-nginx-local-cert.sh
# Run from project root: secret-management-service
#
# Generates local self-signed TLS certificate for Nginx.
# Output:
#   nginx/certs/nginx.crt
#   nginx/certs/nginx.key
#
# Requires Docker.

set -euo pipefail

CERTS_DIR="nginx/certs"
CERT_FILE="${CERTS_DIR}/nginx.crt"
KEY_FILE="${CERTS_DIR}/nginx.key"

echo "Creating directory: ${CERTS_DIR}"
mkdir -p "${CERTS_DIR}"

if [[ -f "${CERT_FILE}" || -f "${KEY_FILE}" ]]; then
  echo
  echo "Certificate files already exist:"
  echo "  ${CERT_FILE}"
  echo "  ${KEY_FILE}"
  echo
  echo "Delete them first if you want to regenerate:"
  echo "  rm -f nginx/certs/nginx.crt nginx/certs/nginx.key"
  exit 0
fi

echo "Generating self-signed certificate for localhost..."

docker run --rm \
  -v "${PWD}/nginx/certs:/certs" \
  nginx:1.27-alpine \
  sh -c "apk add --no-cache openssl >/dev/null && openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 365 -keyout /certs/nginx.key -out /certs/nginx.crt -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'"

echo
echo "Certificate created successfully:"
echo "  ${CERT_FILE}"
echo "  ${KEY_FILE}"
echo
echo "Do NOT commit nginx/certs to Git."