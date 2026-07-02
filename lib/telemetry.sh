#!/usr/bin/env bash
# lib/telemetry.sh - envio a SIEM y disparo de alertas. Abstrae el destino:
# el modulo NO sabe a que SIEM va; se decide aqui segun platform.conf.

# Flags/config esperados desde platform.conf (con defaults seguros: todo off).
: "${SIEM_ENABLED:=false}"
: "${SIEM_TYPE:=none}"        # splunk | elk_http | syslog | none
: "${SPLUNK_HOST:=}"; : "${SPLUNK_HEC_TOKEN:=}"
: "${ELK_HTTP_URL:=}"
: "${ALERTS_ENABLED:=false}"
: "${ALERT_MIN_SEVERITY:=high}"

_sev_rank() { case "$1" in critical) echo 5;; high) echo 4;; medium) echo 3;; low) echo 2;; *) echo 1;; esac; }

# telemetry_send <json> <status> <severity> <control>
telemetry_send() {
    local json="$1" status="$2" severity="$3" control="$4"

    # 1) SIEM (solo si esta habilitado)
    if [[ "$SIEM_ENABLED" == true ]]; then
        case "$SIEM_TYPE" in
            splunk)
                [[ -n "$SPLUNK_HOST" && -n "$SPLUNK_HEC_TOKEN" ]] && \
                curl -sk --max-time 5 -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN}" \
                    "https://${SPLUNK_HOST}:8088/services/collector/event" \
                    -d "{\"event\": ${json}, \"sourcetype\": \"hardening:event\"}" >/dev/null 2>&1 || true
                ;;
            elk_http)
                [[ -n "$ELK_HTTP_URL" ]] && \
                curl -s --max-time 5 -H 'Content-Type: application/json' \
                    -X POST "$ELK_HTTP_URL" -d "$json" >/dev/null 2>&1 || true
                ;;
            syslog)
                command -v logger >/dev/null && logger -t hardening -- "$json" || true
                ;;
        esac
    fi

    # 2) Alertas (solo fallos por encima del umbral)
    if [[ "$ALERTS_ENABLED" == true && "$status" == "fail" ]]; then
        if [[ "$(_sev_rank "$severity")" -ge "$(_sev_rank "$ALERT_MIN_SEVERITY")" ]]; then
            if declare -F alert_dispatch >/dev/null; then
                alert_dispatch "$severity" "Hardening: $control en ${HOST}" "$json"
            fi
        fi
    fi
}
