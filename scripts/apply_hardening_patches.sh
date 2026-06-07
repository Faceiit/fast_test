#!/usr/bin/env bash
set -euo pipefail

echo "[1/7] Checking git status..."
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Repository has uncommitted changes."
  echo "Commit or stash them before applying patches."
  exit 1
fi

echo "[2/7] Checking patches..."
for patch in \
  patches/001_infra_and_main_hardening.patch \
  patches/002_identity_layer_fixes.patch \
  patches/003_secret_schema_hardening.patch \
  patches/004_auth_security_fixes.patch \
  patches/005_audit_client_docs_fixes.patch
do
  if [[ ! -f "$patch" ]]; then
    echo "Missing patch: $patch"
    exit 1
  fi
done

echo "[3/7] Dry-run patch check..."
for patch in patches/*.patch; do
  echo "Checking $patch"
  git apply --check "$patch"
done

echo "[4/7] Applying patches..."
for patch in patches/*.patch; do
  echo "Applying $patch"
  git apply "$patch"
done

echo "[5/7] Python syntax check..."
python -m compileall app scripts

echo "[6/7] Formatting/linting if ruff is available..."
if command -v ruff >/dev/null 2>&1; then
  ruff format .
  ruff check .
else
  echo "ruff is not installed, skipping."
fi

echo "[7/7] Done. Review changes with:"
echo "git diff"
