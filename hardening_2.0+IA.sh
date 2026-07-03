#!/usr/bin/env bash
#
# ==============================================================================
#  hardening_2.0+IA.sh - Orquestador de la Linux Hardening Platform
# ==============================================================================
#  Framework modular, NO destructivo y preparado para IA.
#
#  MODO INTERACTIVO (por defecto): muestra PRIMERO el menu principal con todos
#  los modulos. NO escanea nada automaticamente. Vos elegis:
#    - un modulo puntual (audita -> muestra cambios -> confirmas -> feedback),
#    - "E" para un escaneo general del sistema,
#    - "T" para aplicar todos los modulos.
#
#  MODO BATCH (cron): --audit | --dry-run | --apply [--profile X] [--module id]
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FRAMEWORK_VERSION; FRAMEWORK_VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo 2.0.0)"

MODE=""; PROFILE=""; ONLY_MODULE=""; export ASSUME_YES="false"

usage() {
    cat <<EOF
hardening_2.0+IA.sh v${FRAMEWORK_VERSION} - Linux Hardening Platform

Uso:
  sudo ./hardening_2.0+IA.sh                 # MENU INTERACTIVO (recomendado)
  sudo ./hardening_2.0+IA.sh --audit         # batch: escaneo (solo lectura)
  sudo ./hardening_2.0+IA.sh --apply [...]   # batch: aplica

Opciones batch:
  --audit | --dry-run | --apply
  --profile <n>   Limita a los modulos del perfil (config/profiles/<n>.profile).
  --module <id>   Ejecuta solo un modulo (ej: ssh).
  --yes           Responde 'si' a las confirmaciones.
  --version | -h | --help
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

# Decidir el modo ANTES de cargar librerias (core.sh fija MODE=audit por defecto).
if [[ -n "$MODE" || -n "$ONLY_MODULE" ]]; then RUN_MODE="batch"; else RUN_MODE="interactive"; fi

# --- Cargar librerias ---
# shellcheck source=/dev/null
for l in core backup state report telemetry; do source "${SCRIPT_DIR}/lib/${l}.sh"; done
[[ -f "${SCRIPT_DIR}/integrations/alerts/dispatch.sh" ]] && source "${SCRIPT_DIR}/integrations/alerts/dispatch.sh"
# shellcheck source=/dev/null
[[ -f "${SCRIPT_DIR}/config/platform.conf" ]] && source "${SCRIPT_DIR}/config/platform.conf"

if [[ "${EUID}" -ne 0 ]]; then err "Ejecutar como root: sudo ./hardening_2.0+IA.sh"; exit 1; fi

# --- Contexto del host ---
export HOST; HOST="$(hostname)"
export OS_NAME="Linux"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release; OS_NAME="${PRETTY_NAME:-Linux}"
fi
export RUN_ID; RUN_ID="$(date +%s | tail -c 6)$RANDOM"; export RUN_ID="${RUN_ID:0:8}"

REPORT_DIR="${SCRIPT_DIR}/reports/${HOST}"; mkdir -p "$REPORT_DIR"
export EVENTS_FILE="${REPORT_DIR}/events_${RUN_ID}.jsonl"
export SUMMARY_FILE="${REPORT_DIR}/resumen_${RUN_ID}.txt"
export LOG_FILE="${REPORT_DIR}/run_${RUN_ID}.log"
export BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M)"
: >"$EVENTS_FILE"
state_init

# ==============================================================================
# Descubrimiento de modulos (id, archivo, descripcion) respetando perfil/config
# ==============================================================================
declare -a MODULE_IDS=()
declare -A MOD_FILE=() MOD_DESC=() MOD_FAILS=() MOD_TOTAL=()
declare -a PROFILE_MODULES=()
SCANNED=false

if [[ -n "$PROFILE" && -f "${SCRIPT_DIR}/config/profiles/${PROFILE}.profile" ]]; then
    mapfile -t PROFILE_MODULES < <(grep -vE '^\s*(#|$)' "${SCRIPT_DIR}/config/profiles/${PROFILE}.profile")
fi

_module_enabled() {
    local id="$1"
    [[ -n "$ONLY_MODULE" && "$id" != "$ONLY_MODULE" ]] && return 1
    if [[ ${#PROFILE_MODULES[@]} -gt 0 ]]; then
        printf '%s\n' "${PROFILE_MODULES[@]}" | grep -qx "$id" || return 1
    fi
    local cf="${SCRIPT_DIR}/config/modules.d/${id}.conf"
    if [[ -f "$cf" ]]; then MODULE_ENABLED=true; source "$cf"; [[ "${MODULE_ENABLED}" == false ]] && return 1; fi
    return 0
}

discover_modules() {
    MODULE_IDS=(); shopt -s nullglob
    local mod id desc
    for mod in "${SCRIPT_DIR}"/modules/*.sh; do
        id="$(basename "$mod" .sh)"; id="${id#*-}"
        _module_enabled "$id" || continue
        # shellcheck source=/dev/null
        source "$mod"
        desc="sin descripcion"
        [[ "$(type -t module_describe)" == function ]] && desc="$(module_describe)"
        MODULE_IDS+=("$id"); MOD_FILE["$id"]="$mod"; MOD_DESC["$id"]="$desc"
    done
    shopt -u nullglob
}

# ==============================================================================
# Escaneo general (audita todos los modulos, bajo demanda)
# ==============================================================================
scan_system() {
    R_PASS=0; R_FAIL=0; R_APPLIED=0; R_SKIPPED=0; R_SCORE_NUM=0; R_SCORE_DEN=0; R_CRITICALS=()
    local id before_fail before_tot
    MODE="audit"
    for id in "${MODULE_IDS[@]}"; do
        # shellcheck source=/dev/null
        source "${MOD_FILE[$id]}"
        before_fail="$R_FAIL"; before_tot="$((R_PASS + R_FAIL))"
        title "Escaneando: ${MODULE_ID:-$id}"
        [[ "$(type -t module_audit)" == function ]] && module_audit
        MOD_FAILS["$id"]="$(( R_FAIL - before_fail ))"
        MOD_TOTAL["$id"]="$(( (R_PASS + R_FAIL) - before_tot ))"
    done
    report_posture
    metrics_save "${STATE_DIR:-/var/lib/hardening}/last.metrics"
    baseline_capture
    report_delta
    SCANNED=true; LAST_SCORE="$(report_score)"
}

# ==============================================================================
# Presentacion
# ==============================================================================
print_intro() {
    clear 2>/dev/null || true
    printf '%b' "$C_BLUE"
    cat <<EOF

  ################################################################
  #          LINUX HARDENING PLATFORM   v${FRAMEWORK_VERSION}
  ################################################################
EOF
    printf '%b' "$C_RESET"
    note "  Fortalecimiento MODULAR y controlado de este endpoint."
    note "  Elegis que mejorar: nada se aplica sin tu confirmacion, y todo se respalda."
    info "Host: ${HOST}  |  OS: ${OS_NAME}  |  run_id: ${RUN_ID}"
}

_menu_score() { echo "${LAST_SCORE:--}"; }

print_menu() {
    local sep="════════════════════════════════════════════════════════════════"
    printf '\n%b  %s%b\n' "$C_BLUE" "$sep" "$C_RESET"
    if [[ "$SCANNED" == true ]]; then
        printf '%b  MENU PRINCIPAL%b   (postura tras el ultimo escaneo: %b%s/100%b)\n' \
            "$C_BLUE" "$C_RESET" "$C_WHITE" "$(_menu_score)" "$C_RESET"
    else
        printf '%b  MENU PRINCIPAL%b   (sin escanear: usa %bE%b para un escaneo general)\n' \
            "$C_BLUE" "$C_RESET" "$C_WHITE" "$C_RESET"
    fi
    printf '%b  %s%b\n\n' "$C_BLUE" "$sep" "$C_RESET"

    local i id st
    for i in "${!MODULE_IDS[@]}"; do
        id="${MODULE_IDS[$i]}"
        st=""
        if [[ "$SCANNED" == true ]]; then
            if [[ "${MOD_FAILS[$id]:-0}" -eq 0 ]]; then
                st="$(printf '%b[OK]%b' "$C_GREEN" "$C_RESET")"
            else
                st="$(printf '%b[%s a mejorar]%b' "$C_RED" "${MOD_FAILS[$id]}" "$C_RESET")"
            fi
        fi
        printf '  %b%2d »%b %-10s %s %s\n' "$C_WHITE" "$((i+1))" "$C_RESET" "$id" "${MOD_DESC[$id]}" "$st"
    done

    printf '\n%b  %s%b\n' "$C_BLUE" "$sep" "$C_RESET"
    printf '  %bE »%b Escaneo general   %bI »%b Resumen IA   %bB »%b Reiniciar baseline   %bT »%b Aplicar TODO   %bQ »%b Salir\n' \
        "$C_WHITE" "$C_RESET" "$C_WHITE" "$C_RESET" "$C_WHITE" "$C_RESET" "$C_WHITE" "$C_RESET" "$C_WHITE" "$C_RESET"
    printf '%b  %s%b\n' "$C_BLUE" "$sep" "$C_RESET"
}

# ==============================================================================
# Ejecucion interactiva de UN modulo: preview -> confirmacion -> apply -> feedback
# ==============================================================================
run_module_interactive() {
    local id="$1"
    MODULE_KIND="remediate"   # default; los modulos de medicion lo cambian a "measure"
    # shellcheck source=/dev/null
    source "${MOD_FILE[$id]}"
    title "Modulo: ${MODULE_ID}  (v${MODULE_VERSION:-?}, severidad ${MODULE_SEVERITY:-?})"
    [[ "$(type -t module_describe)" == function ]] && info "$(module_describe)"

    note "  --- Estado actual (auditoria) ---"
    MODE="audit"; local before_fail="$R_FAIL" before_tot="$((R_PASS+R_FAIL))"
    module_audit
    local this_fails="$(( R_FAIL - before_fail ))"
    MOD_FAILS["$id"]="$this_fails"; MOD_TOTAL["$id"]="$(( (R_PASS+R_FAIL) - before_tot ))"

    if [[ "$this_fails" -eq 0 ]]; then
        ok "Este modulo ya cumple. No hay cambios que aplicar."
        return 0
    fi

    if [[ "${MODULE_KIND:-remediate}" == "measure" ]]; then
        info "Modulo de MEDICION: reporta el estado real (no aplica cambios)."
        info "Para MEJORAR: elegi el modulo correspondiente del menu (ssh, network, patches...),"
        info "o usa la opcion 'T' del menu para aplicar TODAS las mejoras de una vez."
        return 0
    fi

    note "  --- Que va a pasar si aplicas ---"
    info "Se remediaran los puntos en FAIL de este modulo."
    info "Se crea un backup con fecha antes de tocar nada, en: ${BACKUP_DIR}"
    info "Es idempotente: no repite ni pisa lo ya endurecido."

    MODE="apply"
    if ! core_confirm "Aplicar remediaciones del modulo '${MODULE_ID}'?"; then
        warn "Cancelado. No se aplico ningun cambio."
        return 0
    fi

    [[ "$(type -t module_apply)" == function ]] && module_apply

    note "  --- Resultado (re-auditoria) ---"
    MODE="audit"; before_fail="$R_FAIL"
    module_audit
    MOD_FAILS["$id"]="$(( R_FAIL - before_fail ))"
    if [[ "${MOD_FAILS[$id]}" -eq 0 ]]; then
        ok "Modulo '${MODULE_ID}': todos los controles en verde."
    else
        warn "Modulo '${MODULE_ID}': quedan ${MOD_FAILS[$id]} punto(s) por revisar manualmente."
    fi
}

apply_all_interactive() {
    title "APLICAR TODOS LOS MODULOS"
    warn "Se aplicaran remediaciones en TODOS los modulos."
    info "Recomendado: manten una segunda sesion SSH abierta (SSH/firewall)."
    MODE="apply"
    if ! core_confirm "Confirmas aplicar TODO el hardening ahora?"; then warn "Cancelado."; return 0; fi
    local prev="$ASSUME_YES"; ASSUME_YES="true"
    local id
    for id in "${MODULE_IDS[@]}"; do
        # shellcheck source=/dev/null
        source "${MOD_FILE[$id]}"
        title "Modulo: ${MODULE_ID}"
        [[ "$(type -t module_describe)" == function ]] && info "$(module_describe)"
        MODE="apply"; [[ "$(type -t module_apply)" == function ]] && module_apply
    done
    ASSUME_YES="$prev"
    ok "Hardening completo aplicado. Usa 'E' para re-escanear y ver el nuevo score."
}

# ==============================================================================
# Bucle interactivo: MENU PRIMERO, sin escaneo automatico
# ==============================================================================
run_interactive() {
    print_intro
    local opt
    while true; do
        print_menu
        read -r -p "$(printf '%b  Selecciona una opcion: %b' "$C_WHITE" "$C_RESET")" opt
        case "${opt^^}" in
            Q) break ;;
            E) info "Escaneo general del sistema..."; scan_system; report_summary ;;
            B) baseline_reset ;;
            I)
                if [[ "$SCANNED" == true ]]; then
                    info "Correlacionando con Wazuh (si esta configurado)..."
                    bash "${SCRIPT_DIR}/ai/wazuh_correlate.sh" || true
                    info "Generando informe con IA..."
                    bash "${SCRIPT_DIR}/ai/summarize.sh" "${SUMMARY_FILE%.txt}.json"
                else
                    warn "Primero hace un escaneo general (E) para tener datos que resumir."
                fi
                ;;
            T) apply_all_interactive ;;
            ''|*[!0-9]*)
                [[ "${opt^^}" =~ ^[EIBTQ]$ ]] || warn "Opcion no valida. Usa un numero, E, I, B, T o Q." ;;
            *)
                local idx="$((opt-1))"
                if [[ "$idx" -ge 0 && "$idx" -lt "${#MODULE_IDS[@]}" ]]; then
                    run_module_interactive "${MODULE_IDS[$idx]}"
                else
                    warn "Numero fuera de rango."
                fi
                ;;
        esac
    done
    info "Reportes en: ${REPORT_DIR}"
    ok "Hasta luego."
}

# ==============================================================================
# Modo batch (no interactivo) para cron/automatizacion
# ==============================================================================
run_batch() {
    MODE="${MODE:-audit}"
    title "Linux Hardening Platform v${FRAMEWORK_VERSION} (batch: ${MODE})"
    info "Host: ${HOST} | OS: ${OS_NAME} | run_id: ${RUN_ID}"
    local id
    for id in "${MODULE_IDS[@]}"; do
        # shellcheck source=/dev/null
        source "${MOD_FILE[$id]}"
        title "Modulo: ${MODULE_ID:-$id}"
        if [[ "$MODE" == "apply" ]]; then
            [[ "$(type -t module_apply)" == function ]] && module_apply
        else
            [[ "$(type -t module_audit)" == function ]] && module_audit
        fi
    done
    if [[ "$MODE" == "audit" ]]; then
        report_posture
        metrics_save "${STATE_DIR:-/var/lib/hardening}/last.metrics"
        baseline_capture
        report_delta
    fi
    report_summary
    if [[ "${AI_SUMMARY_ENABLED:-false}" == true && -f "${SCRIPT_DIR}/ai/summarize.sh" ]]; then
        bash "${SCRIPT_DIR}/ai/summarize.sh" "${SUMMARY_FILE%.txt}.json" || true
    fi
}

# ==============================================================================
# Punto de entrada
# ==============================================================================
discover_modules
if [[ ${#MODULE_IDS[@]} -eq 0 ]]; then err "No se encontraron modulos habilitados."; exit 1; fi

if [[ "$RUN_MODE" == "batch" ]]; then run_batch; else run_interactive; fi
