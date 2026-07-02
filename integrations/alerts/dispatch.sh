#!/usr/bin/env bash
# integrations/alerts/dispatch.sh - dispatcher multicanal con anti-ruido.
: "${ALERT_CHANNELS:=}"          # ej: "telegram email"
: "${ALERT_DEDUPE_DIR:=/tmp/hardening_alerts}"

_alert_dedupe() {  # evita repetir la misma alerta en la misma corrida
    mkdir -p "$ALERT_DEDUPE_DIR"
    local key; key="$(echo "$1" | md5sum | awk '{print $1}')"
    local f="${ALERT_DEDUPE_DIR}/${key}"
    [[ -f "$f" ]] && return 1
    touch "$f"; return 0
}

alert_dispatch() {
    local severity="$1" title="$2" body="$3"
    _alert_dedupe "$title" || return 0
    local ch
    for ch in ${ALERT_CHANNELS}; do
        case "$ch" in
            telegram) alert_telegram "$title" "$body" ;;
            email)    alert_email    "$title" "$body" ;;
            *) : ;;
        esac
    done
}

alert_telegram() {  # requiere TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en platform.conf
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] || return 0
    curl -s --max-time 5 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        --data-urlencode text="[$1] $2" >/dev/null 2>&1 || true
}

alert_email() {  # requiere msmtp/sendmail configurado y ALERT_EMAIL_TO
    [[ -n "${ALERT_EMAIL_TO:-}" ]] || return 0
    command -v sendmail >/dev/null || return 0
    printf 'Subject: %s\n\n%s\n' "$1" "$2" | sendmail "${ALERT_EMAIL_TO}" 2>/dev/null || true
}
