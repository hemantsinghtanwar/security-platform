#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/security-platform"
VENV_DIR="$APP_DIR/venv"
CONFIG_DIR="/etc/security-platform"
CONFIG_FILE="$CONFIG_DIR/config.yml"
DATA_DIR="/var/lib/security-platform"
LOG_DIR="/var/log/security-platform"
SERVICE_FILE="/etc/systemd/system/security-platform.service"

ADMIN_USER="${SECURITY_PLATFORM_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${SECURITY_PLATFORM_ADMIN_PASSWORD:-}"
SMTP_HOST="${SECURITY_PLATFORM_SMTP_HOST:-localhost}"
SMTP_PORT="${SECURITY_PLATFORM_SMTP_PORT:-25}"
SMTP_SENDER="${SECURITY_PLATFORM_SMTP_SENDER:-security-platform@localhost}"
JWT_SECRET="${SECURITY_PLATFORM_JWT_SECRET:-}"
PYTHON_BIN="${SECURITY_PLATFORM_PYTHON_BIN:-}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root."
  exit 1
fi

if [[ -z "$PYTHON_BIN" ]]; then
  for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [[ -z "$PYTHON_BIN" ]]; then
  echo "No usable Python 3 interpreter found."
  exit 1
fi

if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
then
  echo "Python 3.11 or newer is required. Current interpreter: $PYTHON_BIN"
  "$PYTHON_BIN" --version || true
  echo "Install Python 3.11+ and rerun with SECURITY_PLATFORM_PYTHON_BIN=python3.11 ./install.sh"
  exit 1
fi

if [[ -z "$JWT_SECRET" ]]; then
  JWT_SECRET="$("$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
fi

if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD="$("$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
)"
fi

mkdir -p "$APP_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

if [[ -f "./pyproject.toml" ]]; then
  cp -a . "$APP_DIR"
else
  ARCHIVE_URL="${SECURITY_PLATFORM_ARCHIVE_URL:-}"
  if [[ -z "$ARCHIVE_URL" ]]; then
    echo "Set SECURITY_PLATFORM_ARCHIVE_URL when running install.sh remotely."
    exit 1
  fi
  TMP_ARCHIVE="$(mktemp)"
  curl -fsSL "$ARCHIVE_URL" -o "$TMP_ARCHIVE"
  tar -xzf "$TMP_ARCHIVE" -C "$APP_DIR" --strip-components=1
fi

 "$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

if [[ ! -f "$CONFIG_FILE" ]]; then
  cp "$APP_DIR/config/security-platform.example.yml" "$CONFIG_FILE"
fi

"$VENV_DIR/bin/python" - <<PY
from pathlib import Path
import yaml

path = Path("$CONFIG_FILE")
data = yaml.safe_load(path.read_text())
data["api"]["jwt_secret"] = "$JWT_SECRET"
data["smtp"]["host"] = "$SMTP_HOST"
data["smtp"]["port"] = int("$SMTP_PORT")
data["smtp"]["sender"] = "$SMTP_SENDER"
path.write_text(yaml.safe_dump(data, sort_keys=False))
PY

cp "$APP_DIR/systemd/security-platform.service" "$SERVICE_FILE"

export SECURITY_PLATFORM_CONFIG="$CONFIG_FILE"
"$VENV_DIR/bin/python" -m core.cli init-db
"$VENV_DIR/bin/python" -m core.cli create-admin --username "$ADMIN_USER" --password "$ADMIN_PASSWORD"

systemctl daemon-reload
systemctl enable --now security-platform.service

echo "Installation complete."
echo "Dashboard: https://$(hostname -f 2>/dev/null || hostname):8443/"
echo "Admin username: $ADMIN_USER"
echo "Admin password: $ADMIN_PASSWORD"
echo "Config file: $CONFIG_FILE"
