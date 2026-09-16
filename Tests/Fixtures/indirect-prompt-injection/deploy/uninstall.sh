#!/usr/bin/env bash
#
# Remove the AgentReins indirect-prompt-injection field-test range.
#
# Run as root:  ./deploy/uninstall.sh [--purge] [--keep-dns]
#
#   default      removes the service, the vhost and the certificate.
#                Preserves the beacon log by copying it to /root first,
#                because the log *is* the test evidence.
#   --purge      also deletes /opt/ipi-range and /var/lib/ipi-range.
#   --keep-dns   leaves the lab.cyberstroll.top A record in place.
#
set -euo pipefail

DOMAIN="lab.cyberstroll.top"
APP_DIR="/opt/ipi-range"
STATE_DIR="/var/lib/ipi-range"
UNIT="/etc/systemd/system/ipi-range.service"
NGINX_AVAIL="/etc/nginx/sites-available/${DOMAIN}"
NGINX_ENABLED="/etc/nginx/sites-enabled/${DOMAIN}"
VOLC_DIR="/opt/volc-dns"
ZONE="cyberstroll.top"

PURGE=0
KEEP_DNS=0
for arg in "$@"; do
    case "$arg" in
        --purge)    PURGE=1 ;;
        --keep-dns) KEEP_DNS=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# --------------------------------------------------------------------------- #
step "1/6  Preserve the beacon log"
# --------------------------------------------------------------------------- #
EVIDENCE="/root/ipi-range-evidence-$(date +%Y%m%d-%H%M%S).jsonl"
if [ -s "$STATE_DIR/hits.jsonl" ]; then
    cp "$STATE_DIR/hits.jsonl" "$EVIDENCE"
    chmod 600 "$EVIDENCE"
    echo "    $(wc -l < "$EVIDENCE") beacon(s) saved to $EVIDENCE"
else
    echo "    no beacons recorded; nothing to preserve"
fi

# --------------------------------------------------------------------------- #
step "2/6  Stop and remove the service"
# --------------------------------------------------------------------------- #
systemctl disable --now ipi-range.service >/dev/null 2>&1 || true
[ -f "$UNIT" ] && rm -f "$UNIT"
systemctl daemon-reload
systemctl reset-failed ipi-range.service 2>/dev/null || true
echo "    service removed"

# --------------------------------------------------------------------------- #
step "3/6  Remove the nginx vhost"
# --------------------------------------------------------------------------- #
rm -f "$NGINX_ENABLED" "$NGINX_AVAIL"
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    echo "    vhost removed, nginx reloaded"
else
    echo "    WARNING: nginx config invalid after removal; inspect manually" >&2
fi

# --------------------------------------------------------------------------- #
step "4/6  Revoke and delete the certificate"
# --------------------------------------------------------------------------- #
if [ -d "/etc/letsencrypt/live/${DOMAIN}" ]; then
    certbot delete --cert-name "$DOMAIN" --non-interactive || \
        echo "    WARNING: certbot delete failed; remove manually"
else
    echo "    no certificate present"
fi

# --------------------------------------------------------------------------- #
step "5/6  Remove the DNS record"
# --------------------------------------------------------------------------- #
if [ "$KEEP_DNS" = "1" ]; then
    echo "    --keep-dns given; leaving ${DOMAIN} in place"
elif [ -x "$VOLC_DIR/venv/bin/python" ]; then
    rid="$(cd "$VOLC_DIR" && ./venv/bin/python dns_manager.py list-records --zone "$ZONE" 2>/dev/null \
        | awk '/^  ✅ lab /{print $NF}' | tr -d ']' | sed 's/ID://')"
    if [ -n "$rid" ]; then
        ( cd "$VOLC_DIR" && ./venv/bin/python dns_manager.py delete-record \
            --zone "$ZONE" --record-id "$rid" ) || echo "    WARNING: DNS delete failed"
    else
        echo "    no lab record found"
    fi
else
    echo "    volc toolkit not found at $VOLC_DIR; remove the DNS record manually"
fi

# --------------------------------------------------------------------------- #
step "6/6  Remove application directories"
# --------------------------------------------------------------------------- #
if [ "$PURGE" = "1" ]; then
    rm -rf "$APP_DIR" "$STATE_DIR"
    echo "    $APP_DIR and $STATE_DIR removed"
else
    echo "    kept $APP_DIR and $STATE_DIR (re-run with --purge to delete)"
fi

cat <<EOF

================================================================================
Teardown complete.
  evidence : $EVIDENCE
  service  : $(systemctl is-enabled ipi-range.service 2>&1 || true)
================================================================================
EOF
