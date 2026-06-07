#!/usr/bin/env bash
set -euo pipefail

echo "[1/6] Python syntax check..."
python -m compileall app scripts

echo "[2/6] Ruff check if available..."
if command -v ruff >/dev/null 2>&1; then
  ruff format --check .
  ruff check .
else
  echo "ruff is not installed, skipping."
fi

echo "[3/6] Docker compose config check..."
docker compose config >/dev/null

echo "[4/6] Build containers..."
docker compose build

echo "[5/6] Start postgres..."
docker compose up -d postgres

echo "[6/6] Run migrations..."
docker compose run --rm api alembic upgrade head

echo "Project checks passed."

