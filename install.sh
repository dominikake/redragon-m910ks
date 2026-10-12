#!/usr/bin/env bash
# Install the Redragon M910-KS battery reader and its refresh timer.
#
# Copies the tools to ~/.local/share/redragon-m910ks/ (so the repo can be
# moved or deleted without breaking the timer), installs the systemd user
# units, and enables the timer.
#
#   ./install.sh            install + enable timer
#   ./install.sh --no-timer install files only
#   ./install.sh --uninstall
#
# Assumes docs/SETUP.md has already been followed (udev rule + input group).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.local/share/redragon-m910ks"
UNIT_DIR="$HOME/.config/systemd/user"

die() { echo "error: $*" >&2; exit 1; }

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl --user disable --now redragon-battery.timer 2>/dev/null || true
    rm -f "$UNIT_DIR/redragon-battery.service" "$UNIT_DIR/redragon-battery.timer"
    systemctl --user daemon-reload
    echo "Removed timer and units. Data left in ${DEST} and history dir."
    echo "To fully remove: rm -rf '$DEST' ~/.local/state/redragon-m910ks"
    exit 0
fi

echo "==> installing tools to $DEST"
mkdir -p "$DEST"
cp "$REPO"/tools/{sinowealth,history,battery,plot,confirm}.py "$DEST/"
chmod +x "$DEST"/*.py

echo "==> installing systemd user units"
mkdir -p "$UNIT_DIR"
cp "$REPO"/systemd/redragon-battery.{service,timer} "$UNIT_DIR/"
systemctl --user daemon-reload

if [[ "${1:-}" == "--no-timer" ]]; then
    echo "==> files installed; timer not enabled (--no-timer)"
    exit 0
fi

echo "==> enabling + starting timer"
systemctl --user enable --now redragon-battery.timer

echo
echo "Installed. Check status with:"
echo "  systemctl --user status redragon-battery.timer"
echo "  journalctl --user -u redragon-battery.service -n 20"
echo
echo "Try one read now:"
echo "  python3 $DEST/battery.py --retries 3"
echo "View the curve with:"
echo "  python3 $REPO/tools/plot.py"