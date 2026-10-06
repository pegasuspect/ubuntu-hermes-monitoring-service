#!/usr/bin/env bash
# Install hermes-sentinel as a systemd *user* service that runs at boot
# without login (enables lingering). No root required.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC="$PROJECT_DIR/systemd/hermes-sentinel.service"
UNIT_DST="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/hermes-sentinel.service"
ENV_SRC="$PROJECT_DIR/.env"
ENV_DST_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hermes-sentinel"
ENV_DST="$ENV_DST_DIR/env"

echo "==> hermes-sentinel installer"
echo "    project: $PROJECT_DIR"

# 0) sanity: personal values must be configured somewhere
if [ ! -f "$ENV_SRC" ] && [ ! -f "$ENV_DST" ] && \
   [ ! -f "$PROJECT_DIR/config/sentinel.local.yaml" ]; then
    echo "WARNING: no personal configuration found." >&2
    echo "  Copy .env.example to .env (or config/sentinel.local.yaml.example" >&2
    echo "  to config/sentinel.local.yaml) and set your Signal number." >&2
fi

# 1) systemd user unit (rewrite the working-dir placeholder)
mkdir -p "$(dirname "$UNIT_DST")"
sed "s|%h/projects/ubuntu-hermes-monitoring-service|$PROJECT_DIR|g" \
    "$UNIT_SRC" > "$UNIT_DST"
echo "    installed unit: $UNIT_DST"

# 2) ship the .env (if present) to the location the unit reads
if [ -f "$ENV_SRC" ]; then
    mkdir -p "$ENV_DST_DIR"
    cp "$ENV_SRC" "$ENV_DST"
    chmod 600 "$ENV_DST"
    echo "    installed env: $ENV_DST"
fi

# 3) linger so user services start at boot without login
if ! loginctl show-user "$USER" 2>/dev/null | grep -q '^Linger=yes'; then
    echo "==> enabling linger (boot-without-login) for $USER"
    loginctl enable-linger "$USER"
else
    echo "    linger already enabled"
fi

# 4) reload and start
systemctl --user daemon-reload
systemctl --user enable --now hermes-sentinel.service

echo "==> done. status:"
systemctl --user --no-pager --lines=5 status hermes-sentinel.service || true
echo
echo "Useful commands:"
echo "  python3 -m hermes_sentinel check        # verify data sources"
echo "  python3 -m hermes_sentinel test-signal # send a test alert"
echo "  journalctl --user -u hermes-sentinel -f"
echo "  tail -f ~/.local/state/hermes-sentinel/sentinel.log"