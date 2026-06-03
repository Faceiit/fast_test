# scripts/generate-nginx-local-cert.ps1
# Run from project root: secret-management-service
#
# Generates local self-signed TLS certificate for Nginx.
# Output:
#   nginx/certs/nginx.crt
#   nginx/certs/nginx.key
#
# Requires Docker.

$ErrorActionPreference = "Stop"

$certsDir = "nginx\certs"
$certFile = "$certsDir\nginx.crt"
$keyFile = "$certsDir\nginx.key"

Write-Host "Creating directory: $certsDir"
New-Item -ItemType Directory -Force $certsDir | Out-Null

if ((Test-Path $certFile) -or (Test-Path $keyFile)) {
    Write-Host ""
    Write-Host "Certificate files already exist:"
    Write-Host "  $certFile"
    Write-Host "  $keyFile"
    Write-Host ""
    Write-Host "Delete them first if you want to regenerate:"
    Write-Host "  Remove-Item .\nginx\certs\nginx.crt, .\nginx\certs\nginx.key"
    exit 0
}

Write-Host "Generating self-signed certificate for localhost..."

docker run --rm `
    -v "${PWD}\nginx\certs:/certs" `
    nginx:1.27-alpine `
    sh -c "apk add --no-cache openssl >/dev/null && openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 365 -keyout /certs/nginx.key -out /certs/nginx.crt -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'"

Write-Host ""
Write-Host "Certificate created successfully:"
Write-Host "  $certFile"
Write-Host "  $keyFile"
Write-Host ""
Write-Host "Do NOT commit nginx/certs to Git."