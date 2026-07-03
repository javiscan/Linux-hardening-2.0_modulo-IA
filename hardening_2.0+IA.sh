#!/usr/bin/env bash
#
# ==============================================================================
#  hardening_2.0+IA.sh - Orquestador de la Linux Hardening Platform
# ==============================================================================
#  Framework modular, NO destructivo y preparado para IA.
#
#  MODO INTERACTIVO (por defecto, sin argumentos):
#    intro -> escaneo inicial -> menu -> elegis un modulo o todos.
#    Cada modulo: muestra que cambiaria -> pide confirmacion -> aplica -> feedback.
#
#  MODO BATCH (para cron/automatizacion):
#    --audit | --dry-run | --apply [--profile X] [--module id] [--yes]
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FRAMEWORK_VERSION; FRAMEWORK_VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo 2.0.0)"

# --- Parametros ---
MODE=""            # vacio => interactivo. audit|dry-run|apply => batch
PROFILE=""
ONLY_MODULE=""
export ASSUME_YES="false"

usage() {
    cat <<EOF
hardening_2.0+IA.sh v${FRAMEWORK_VERSION} - Linux Hardening Platform

Uso:
  sudo ./hardening_2.0+IA.sh                 # MENU INTERACTIVO (recomendado)
  sudo ./hardening_2.0+IA.sh --audit         # batch: solo lectura
  sudo ./hardening_2.0+IA.sh --apply [...]   # batch: aplica

Opciones batch:
  --audit | --dry-run | --apply   Modo no interactivo.
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

# --- Root requerido ---
if [[ "${EUID}" -ne 0 ]]; then err "Ejecutar como root: sudo ./hardening_2.0+IA.sh"; exit 1; fi

# --- Contexto del host ---
export HOST; HOST="$(hostname)"
export OS_NAME="Linux"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release; OS_NAME="${PRETTY_NAME:-Linux}"
fi
export RUN_ID; RUN_ID="$(date +%s | tail -c 6)$RANDOM"; export RUN_ID="${RUN_ID:0:8}"

# --- Rutas de salida ---
REPORT_DIR="${SCRIPT_DIR}/reports/${HOST}"; mkdir -p "$REPORT_DIR"
export EVENTS_FILE="${REPORT_DIR}/events_${RUN_ID}.jsonl"
export SUMMARY_FILE="${REPORT_DIR}/resumen_${RUN_ID}.txt"
export LOG_FILE="${REPORT_DIR}/run_${RUN_ID}.log"
export BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M)"
: >"$EVENTS_FILE"
state_init

# ==============================================================================
# Descubrimiento de modulos (respeta perfil, --module y config)
# ==============================================================================
declare -a MODULE_IDS=()
declare -A MOD_FILE=() MOD_FAILS=() MOD_TOTAL=()
declare -a PROFILE_MODULES=()

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
    local mod id
    for mod in "${SCRIPT_DIR}"/modules/*.sh; do
        id="$(basename "$mod" .sh)"; id="${id#*-}"
        _module_enabled "$id" || continue
        MODULE_IDS+=("$id"); MOD_FILE["$id"]="$mod"
    done
    shopt -u nullglob
}

# ==============================================================================
# Escaneo inicial del sistema (audit de todos los modulos)
# ==============================================================================
scan_system() {
    local verbose="${1:-true}"
    R_PASS=0; R_FAIL=0; R_APPLIED=0; R_SKIPPED=0; R_SCORE_NUM=0; R_SCORE_DEN=0; R_CRITICALS=()
    local id before_fail before_tot
    MODE="audit"
    for id in "${MODULE_IDS[@]}"; do
        # shellcheck source=/dev/null
        source "${MOD_FILE[$id]}"
        before_fail="$R_FAIL"; before_tot="$((R_PASS + R_FAIL))"
        [[ "$verbose" == true ]] && title "Escaneando: ${MODULE_ID:-$id}"
        [[ "$(type -t module_audit)" == function ]] && module_audit
        MOD_FAILS["$id"]="$(( R_FAIL - before_fail ))"
        MOD_TOTAL["$id"]="$(( (R_PASS + R_FAIL) - before_tot ))"
    done
}

# ==============================================================================
# Presentacion
# ==============================================================================
print_intro() {
    clear 2>/dev/null || true
    printf '%b' "$C_BLUE"
    cat <<EOF

  #############################################################
  #         LINUX HARDENING PLATFORM  v${FRAMEWORK_VERSION}
  #############################################################
EOF
    printf '%b' "$C_RESET"
    note "  Fortalece la seguridad de este endpoint de forma MODULAR y controlada."
    note "  Cada modulo audita el estado actual y te deja decidir si aplicar los"
    note "  cambios. Nada se modifica sin tu confirmacion. Todo se respalda."
    info "Host: ${HOST}  |  OS: ${OS_NAME}  |  run_id: ${RUN_ID}"
    note "  Modos: ejecuta un modulo puntual, o TODOS de una vez (opcion T)."
}

print_menu() {
    local score tot=0 fail=0 mid
    for mid in "${MODULE_IDS[@]}"; do tot=$((tot+${MOD_TOTAL[$mid]:-0})); fail=$((fail+${MOD_FAILS[$mid]:-0})); done
    score=100; [[ $tot -gt 0 ]] && score=$(( (tot-fail)*100/tot ))
    printf '\n%b===== MENU DE MODULOS =====%b  (postura actual: %b%s/100%b)\n' \
        "$C_BLUE" "$C_RESET" "$C_WHITE" "$score" "$C_RESET"
    local i id label
    for i in "${!MODULE_IDS[@]}"; do
        id="${MODULE_IDS[$i]}"
        local fails="${MOD_FAILS[$id]:-0}"
        if [[ "$fails" -eq 0 ]]; then
            label="$(printf '%b[OK]%b        cumple' "$C_GREEN" "$C_RESET")"
        else
            label="$(printf '%b[%s hallazgo(s)]%b a mejorar' "$C_RED" "$fails" "$C_RESET")"
        fi
        printf '  %2d) %-12s %s\n' "$((i+1))" "$id" "$label"
    done
    printf '%b' "$C_WHITE"
    note "   T) Aplicar TODOS los modulos     R) Re-escanear"
    note "   S) Ver resumen/score             Q) Salir"
    printf '%b' "$C_RESET"
}

# ==============================================================================
# Ejecucion interactiva de UN modulo: preview -> confirmacion -> apply -> feedback
# ==============================================================================
run_module_interactive() {
    local id="$1"
    # shellcheck source=/dev/null
    source "${MOD_FILE[$id]}"
    title "Modulo: ${MODULE_ID}  (v${MODULE_VERSION:-?}, severidad ${MODULE_SEVERITY:-?})"
    [[ "$(type -t module_describe)" == function ]] && info "$(module_describe)"

    # 1) Preview: mostrar el estado actual (que esta bien y que no)
    note "  --- Estado actual (auditoria) ---"
    MODE="audit"; local before_fail="$R_FAIL" before_tot="$((R_PASS+R_FAIL))"
    module_audit
    local this_fails="$(( R_FAIL - before_fail ))"
    MOD_FAILS["$id"]="$this_fails"
    MOD_TOTAL["$id"]="$(( (R_PASS+R_FAIL) - before_tot ))"

    if [[ "$this_fails" -eq 0 ]]; then
        ok "Este modulo ya cumple. No hay cambios que aplicar."
        return 0
    fi

    # 2) Visto bueno antes de aplicar
    note "  --- Que va a pasar si aplicas ---"
    info "Se remediaran los puntos en FAIL de este modulo."
    info "Antes de tocar cualquier archivo se crea un backup con fecha en:"
    note "    ${BACKUP_DIR}"
    info "La operacion es idempotente: no repite ni pisa lo ya endurecido."

    # 3) Confirmar o cancelar
    MODE="apply"
    if ! core_confirm "Aplicar remediaciones del modulo '${MODULE_ID}'?"; then
        warn "Cancelado. No se aplico ningun cambio."
        return 0
    fi

    # 4) Aplicar
    [[ "$(type -t module_apply)" == function ]] && module_apply

    # 5) Feedback: re-auditar y actualizar estado del menu
    note "  --- Resultado (re-auditoria) ---"
    MODE="audit"; before_fail="$R_FAIL"
    module_audit
    MOD_FAILS["$id"]="$(( R_FAIL - before_fail ))"
    if [[ "${MOD_FAILS[$id]}" -eq 0 ]]; then
        ok "Modulo '${MODULE_ID}': todos los controles en verde."
    else
        warn "Modulo '${MODULE_ID}': quedan ${MOD_FAILS[$id]} punto(s) que requieren accion manual."
    fi
}

# Aplicar TODOS los modulos (con un unico visto bueno global)
apply_all_interactive() {
    title "APLICAR TODOS LOS MODULOS"
    warn "Se aplicaran remediaciones en TODOS los modulos listados."
    info "Recomendado: manten una segunda sesion SSH abierta (SSH/firewall)."
    MODE="apply"
    if ! core_confirm "Confirmas aplicar TODO el hardening ahora?"; then
        warn "Cancelado."; return 0
    fi
    local prev="$ASSUME_YES"; ASSUME_YES="true"   # evita repreguntar por cada modulo
    local id
    for id in "${MODULE_IDS[@]}"; do
        # shellcheck source=/dev/null
        source "${MOD_FILE[$id]}"
        title "Modulo: ${MODULE_ID}"
        [[ "$(type -t module_describe)" == function ]] && info "$(module_describe)"
        MODE="apply"; [[ "$(type -t module_apply)" == function ]] && module_apply
    done
    ASSUME_YES="$prev"
    ok "Hardening completo aplicado. Ejecuta 'R' para re-escanear y ver el nuevo score."
}

# ==============================================================================
# Bucle interactivo
# ==============================================================================
run_interactive() {
    print_intro
    info "Realizando escaneo inicial del sistema..."
    scan_system true
    local opt
    while true; do
        print_menu
        read -r -p "$(printf '%bSelecciona una opcion: %b' "$C_WHITE" "$C_RESET")" opt
        case "${opt^^}" in
            Q) break ;;
            T) apply_all_interactive ;;
            R) info "Re-escaneando..."; scan_system true ;;
            S) scan_system true; report_summary ;;
            ''|*[!0-9]*)
                # No es numero puro (y no fue T/R/S/Q)
                [[ "${opt^^}" =~ ^[TRSQ]$ ]] || warn "Opcion no valida." ;;
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
    info "Escaneo final del sistema..."
    scan_system true
    report_summary
    info "Eventos: ${EVENTS_FILE}"
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

if [[ "$RUN_MODE" == "batch" ]]; then
    run_batch
else
    run_interactive
fi
