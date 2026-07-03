#!/usr/bin/env bash
# ==============================================================================
#  ai/wazuh_correlate.sh  -  Nivel 2 IA: correlacion POSTURA <-> AMENAZAS
# ==============================================================================
#  Cruza la postura del hardening (debilidades locales) con las amenazas que ve
#  Wazuh (alertas de Suricata, intentos de login fallidos, CVEs, SCA) y produce
#  hallazgos PRIORIZADOS. No modifica el sistema: solo lee.
#
#  Modos:
#   - En vivo: si WAZUH_* esta configurado, consulta Wazuh (API + Indexer).
#   - Fixture: ai/wazuh_correlate.sh --threat <archivo.json>  (para pruebas/offline)
#
#  Escribe: ${STATE_DIR}/threat_context.txt  (lo consume ai/summarize.sh)
# ==============================================================================
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$SCRIPT_DIR/config/platform.conf" ]] && source "$SCRIPT_DIR/config/platform.conf"
# shellcheck source=/dev/null
[[ -f "$SCRIPT_DIR/config/secrets.env" ]] && source "$SCRIPT_DIR/config/secrets.env"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/integrations/wazuh/wazuh_client.sh"
: "${STATE_DIR:=/var/lib/hardening}"
HOST="$(hostname)"

THREAT_FILE=""
[[ "${1:-}" == "--threat" && -n "${2:-}" ]] && THREAT_FILE="$2"

# --- Construir threat.json desde Wazuh en vivo (best-effort; ajustar a tu version) ---
build_threat_live() {
    wazuh_indexer_available || wazuh_api_available || return 1
    local suricata authfail vuln sca
    suricata="$(wazuh_indexer_count 'rule.groups:ids OR rule.groups:suricata' 2>/dev/null)"
    authfail="$(wazuh_indexer_count 'rule.groups:authentication_failed OR rule.groups:authentication_failures' 2>/dev/null)"
    vuln="$(wazuh_indexer_count 'rule.groups:vulnerability-detector AND data.vulnerability.severity:Critical' 2>/dev/null)"
    sca=""   # el % SCA se obtiene por agente via API; se deja opcional
    [[ -z "$suricata$authfail$vuln" ]] && return 1
    mkdir -p "$STATE_DIR"
    cat > "${STATE_DIR}/threat.json" <<EOF
{"suricata_alerts": ${suricata:-0}, "auth_failures": ${authfail:-0}, "vuln_critical": ${vuln:-0}, "sca_score": ${sca:-0}}
EOF
    THREAT_FILE="${STATE_DIR}/threat.json"; return 0
}

if [[ -z "$THREAT_FILE" ]]; then build_threat_live || true; fi

if [[ -z "$THREAT_FILE" || ! -f "$THREAT_FILE" ]]; then
    echo "[wazuh] Sin datos de Wazuh (configura WAZUH_* en config/secrets.env o usa --threat <file>). Se omite la correlacion."
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "[wazuh] python3 requerido para parsear datos." >&2; exit 0; }
eval "$(python3 - "$THREAT_FILE" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: d={}
def gi(k):
    try: return int(d.get(k,0) or 0)
    except: return 0
print(f'SURICATA={gi("suricata_alerts")}')
print(f'AUTHFAIL={gi("auth_failures")}')
print(f'WVULN={gi("vuln_critical")}')
print(f'SCA={gi("sca_score")}')
PY
)"

# --- Debilidades locales (del ultimo escaneo del hardening) ---
EVENTS="$(ls -t "$SCRIPT_DIR/reports/$HOST"/events_*.jsonl 2>/dev/null | head -n1)"
has_fail() { [[ -n "$EVENTS" ]] && grep -q "\"control_id\":\"$1\"[^}]*\"status\":\"fail\"" "$EVENTS"; }

# --- Reglas de correlacion (postura x amenaza) ---
declare -a FINDINGS=()
if [[ "$SURICATA" -gt 0 ]] && has_fail ufw_enabled; then
    FINDINGS+=("CRITICO | ${SURICATA} alertas de red (Suricata) CON firewall inactivo -> activar UFW ya (modulo network).")
fi
if [[ "$AUTHFAIL" -gt 0 ]] && has_fail ssh_password_auth; then
    FINDINGS+=("ALTO | ${AUTHFAIL} intentos de login fallidos CON SSH por contrasena habilitado -> forzar clave publica (modulo ssh).")
fi
if [[ "$WVULN" -gt 0 ]]; then
    FINDINGS+=("CRITICO | ${WVULN} CVE criticas segun Wazuh -> parchear (modulo patches).")
fi
if [[ "$SURICATA" -gt 0 ]] && has_fail edr_present; then
    FINDINGS+=("ALTO | Trafico sospechoso SIN EDR/agente confirmado -> desplegar agente (modulo edr).")
fi
if [[ "$SCA" -gt 0 && "$SCA" -lt 80 ]]; then
    FINDINGS+=("MEDIO | Cumplimiento CIS (Wazuh SCA) ${SCA}% < 80% -> aplicar mas modulos de hardening.")
fi
[[ ${#FINDINGS[@]} -eq 0 ]] && FINDINGS+=("OK | Sin correlaciones criticas: la postura cubre las amenazas observadas.")

# --- Enriquecer metricas (el SCA oficial de Wazuh reemplaza el estimado) ---
set_metric() {
    local f="${STATE_DIR}/last.metrics"; mkdir -p "$STATE_DIR"; touch "$f"
    grep -v "^$1=" "$f" > "${f}.tmp" 2>/dev/null || true
    echo "$1=$2" >> "${f}.tmp"; mv "${f}.tmp" "$f"
}
[[ "$SCA" -gt 0 ]] && set_metric cis_compliance "$SCA"
set_metric wazuh_suricata_alerts "$SURICATA"
set_metric wazuh_auth_failures "$AUTHFAIL"
set_metric wazuh_vuln_critical "$WVULN"

# --- Escribir contexto de amenazas (para la IA) + reporte ---
{
    echo "Alertas Suricata (red): ${SURICATA}"
    echo "Intentos de login fallidos: ${AUTHFAIL}"
    echo "CVE criticas (Wazuh): ${WVULN}"
    [[ "$SCA" -gt 0 ]] && echo "Cumplimiento CIS (Wazuh SCA oficial): ${SCA}%"
    echo "Correlaciones priorizadas (postura x amenaza):"
    for f in "${FINDINGS[@]}"; do echo "- ${f}"; done
} > "${STATE_DIR}/threat_context.txt"

echo "=== CORRELACION WAZUH (postura x amenaza) - ${HOST} ==="
cat "${STATE_DIR}/threat_context.txt"
echo "[wazuh] Contexto guardado en ${STATE_DIR}/threat_context.txt (lo usa ai/summarize.sh)."
