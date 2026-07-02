#!/usr/bin/env bash
#
# ==============================================================================
#  hardening_2.0+IA.sh - Orquestador de la Linux Hardening Platform
# ==============================================================================
#  Evolucion modular, no destructiva y lista para IA del hardening base.
#  - Descubre modulos en modules/ y los ejecuta segun perfil/config.
#  - Modos: --audit (default, solo lectura) | --dry-run | --apply
#  - Emite telemetria JSON, envia a SIEM/alertas y genera un resumen por host.
#
#  Uso: sudo ./hardening_2.0+IA.sh [--audit|--dry-run|--apply] [opciones]
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FRAMEWORK_VERSION; FRAMEWORK_VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo 2.0.0)"

# --- Parametros ---
MODE="audit"
PROFILE=""
ONLY_MODULE=""
export ASSUME_YES="false"

usage() {
    cat <<EOF
hardening_2.0+IA.sh v${FRAMEWORK_VERSION} - Linux Hardening Platform

Uso: sudo ./hardening_2.0+IA.sh [modo] [opciones]

Modos:
  --audit      (default) Solo lectura: reporta el estado, no cambia nada.
  --dry-run    Simula las remediaciones sin aplicarlas.
  --apply      Aplica remediaciones (idempotente y con backups).

Opciones:
  --profile <n>   Ejecuta solo los modulos del perfil (config/profiles/<n>.profile).
  --module <id>   Ejecuta solo un modulo (ej: ssh).
  --yes           Responde 'si' a confirmaciones (no interactivo).
  --version       Muestra la version.
  -h, --help      Esta ayuda.

El estado de seguridad se resume al final y se guarda en reports/<host>/.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --audit) MODE="audit" ;;
        --dry-run) MODE="dry-run" ;;
        --apply) MODE="apply" ;;
        --profile) PROFILE="$2"; shift ;;
        --module) ONLY_MODULE="$2"; shift ;;
        --yes) ASSUME_YES="true" ;;
        --version) echo "$FRAMEWORK_VERSION"; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Opcion desconocida: $1"; usage; exit 1 ;;
    esac
    shift
done
export MODE

# --- Cargar librerias ---
# shellcheck source=/dev/null
for l in core backup state report telemetry; do source "${SCRIPT_DIR}/lib/${l}.sh"; done
# Integraciones de alertas (opcional)
[[ -f "${SCRIPT_DIR}/integrations/alerts/dispatch.sh" ]] && source "${SCRIPT_DIR}/integrations/alerts/dispatch.sh"
# Config global (puede sobreescribir flags de SIEM/alertas)
# shellcheck source=/dev/null
[[ -f "${SCRIPT_DIR}/config/platform.conf" ]] && source "${SCRIPT_DIR}/config/platform.conf"

# --- Root requerido (excepto help/version, ya resueltos) ---
if [[ "${EUID}" -ne 0 ]]; then
    err "Ejecutar como root: sudo ./hardening_2.0+IA.sh"
    exit 1
fi

# --- Contexto del host ---
export HOST; HOST="$(hostname)"
export OS_NAME="Linux"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release; OS_NAME="${PRETTY_NAME:-Linux}"
fi
export RUN_ID; RUN_ID="$(date +%s | tail -c 6)$RANDOM"
export RUN_ID="${RUN_ID:0:8}"

# --- Rutas de salida ---
REPORT_DIR="${SCRIPT_DIR}/reports/${HOST}"
mkdir -p "$REPORT_DIR"
export EVENTS_FILE="${REPORT_DIR}/events_${RUN_ID}.jsonl"
export SUMMARY_FILE="${REPORT_DIR}/resumen_${RUN_ID}.txt"
export LOG_FILE="${REPORT_DIR}/run_${RUN_ID}.log"
export BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M)"
: >"$EVENTS_FILE"

state_init

# --- Banner ---
title "Linux Hardening Platform v${FRAMEWORK_VERSION}"
info "Host: ${HOST} | OS: ${OS_NAME} | Modo: ${MODE} | run_id: ${RUN_ID}"
[[ "$MODE" == "apply" ]] && warn "Modo APPLY: se aplicaran remediaciones (idempotentes, con backup en ${BACKUP_DIR})."
[[ "$MODE" != "apply" ]] && info "Modo de solo lectura: no se modifica el sistema."

# --- Seleccion de modulos segun perfil ---
declare -a PROFILE_MODULES=()
if [[ -n "$PROFILE" ]]; then
    pf="${SCRIPT_DIR}/config/profiles/${PROFILE}.profile"
    if [[ -f "$pf" ]]; then
        mapfile -t PROFILE_MODULES < <(grep -vE '^\s*(#|$)' "$pf")
        info "Perfil: ${PROFILE} (${#PROFILE_MODULES[@]} modulos)"
    else
        warn "Perfil '${PROFILE}' no encontrado; se ejecutan todos los modulos."
    fi
fi

module_enabled() {
    local id="$1"
    # Filtro por --module
    [[ -n "$ONLY_MODULE" && "$id" != "$ONLY_MODULE" ]] && return 1
    # Filtro por perfil
    if [[ ${#PROFILE_MODULES[@]} -gt 0 ]]; then
        printf '%s\n' "${PROFILE_MODULES[@]}" | grep -qx "$id" || return 1
    fi
    # Filtro por config/modules.d/<id>.conf (MODULE_ENABLED=false lo desactiva)
    local cf="${SCRIPT_DIR}/config/modules.d/${id}.conf"
    if [[ -f "$cf" ]]; then
        # shellcheck source=/dev/null
        MODULE_ENABLED=true; source "$cf"
        [[ "${MODULE_ENABLED}" == false ]] && return 1
    fi
    return 0
}

# --- Bucle de ejecucion ---
shopt -s nullglob
for mod in "${SCRIPT_DIR}"/modules/*.sh; do
    id="$(basename "$mod" .sh)"; id="${id#*-}"   # 10-ssh -> ssh
    module_enabled "$id" || continue
    # shellcheck source=/dev/null
    source "$mod"
    title "Modulo: ${MODULE_ID:-$id} (${MODULE_VERSION:-?})"
    [[ "$(type -t module_describe)" == function ]] && info "$(module_describe)"
    if [[ "$MODE" == "apply" ]]; then
        [[ "$(type -t module_apply)" == function ]] && module_apply
    else
        [[ "$(type -t module_audit)" == function ]] && module_audit
    fi
done
shopt -u nullglob

# --- Resumen final ---
report_summary
info "Eventos: ${EVENTS_FILE}"
info "Resumen: ${SUMMARY_FILE}"

# --- Hook de IA (Fase 2, opcional y no destructivo: solo lee reportes) ---
if [[ "${AI_SUMMARY_ENABLED:-false}" == true && -f "${SCRIPT_DIR}/ai/summarize.sh" ]]; then
    info "Generando resumen con IA..."
    bash "${SCRIPT_DIR}/ai/summarize.sh" "${SUMMARY_FILE%.txt}.json" || warn "Resumen IA no disponible."
fi

[[ "$MODE" == "apply" ]] && ok "Backups en: ${BACKUP_DIR}"
ok "Ejecucion finalizada."
