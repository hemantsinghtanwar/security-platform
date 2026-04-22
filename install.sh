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

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root."
  exit 1
fi

if [[ -z "$JWT_SECRET" ]]; then
  JWT_SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
fi

if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD="$(python3 - <<'PY'
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

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "$APP_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
  cp "$APP_DIR/config/security-platform.example.yml" "$CONFIG_FILE"
fi

python3 - <<PY
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
