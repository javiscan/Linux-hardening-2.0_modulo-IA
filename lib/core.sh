#!/usr/bin/env bash
# lib/core.sh - utilidades base: colores, logging, modos de ejecucion.
# No destructivo: aqui vive el motor de --audit / --dry-run / --apply.

# Modos (los fija el orquestador): audit | dry-run | apply
: "${MODE:=audit}"
: "${ASSUME_YES:=false}"

if [[ -t 1 ]]; then
    C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'; C_CYAN=$'\033[1;36m'
    C_RED=$'\033[1;31m';  C_WHITE=$'\033[1;37m'; C_RESET=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_CYAN=""; C_RED=""; C_WHITE=""; C_RESET=""
fi

core_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >>"${LOG_FILE:-/dev/null}" 2>/dev/null || true; }
title() { printf '\n%b===== %s =====%b\n' "$C_BLUE" "$1" "$C_RESET"; core_log "TITULO: $1"; }
ok()    { printf '%b[ OK ]%b %s\n' "$C_GREEN" "$C_RESET" "$1"; core_log "OK: $1"; }
info()  { printf '%b[INFO]%b %s\n' "$C_CYAN"  "$C_RESET" "$1"; core_log "INFO: $1"; }
warn()  { printf '%b[WARN]%b %s\n' "$C_RED"   "$C_RESET" "$1"; core_log "WARN: $1"; }
err()   { printf '%b[ERR ]%b %s\n' "$C_RED"   "$C_RESET" "$1" >&2; core_log "ERR: $1"; }
note()  { printf '%b%s%b\n' "$C_WHITE" "$1" "$C_RESET"; }

# ¿Estamos en un modo de solo lectura? (audit o dry-run no escriben)
core_read_only() { [[ "$MODE" == "audit" || "$MODE" == "dry-run" ]]; }

# Ejecuta un comando solo si estamos en modo apply; si no, lo simula.
core_run() {
    if core_read_only; then
        printf '%b[SIMULADO]%b %s\n' "$C_CYAN" "$C_RESET" "$*"
        return 0
    fi
    "$@"
}

core_confirm() {
    local prompt="${1:-Continuar?}"
    [[ "$ASSUME_YES" == true ]] && return 0
    core_read_only && return 1
    local a; read -r -p "$(printf '%b%s [s/N]: %b' "$C_WHITE" "$prompt" "$C_RESET")" a
    [[ "$a" =~ ^([sS][iI]?|[yY])$ ]]
}

# Inserta o reemplaza "clave valor" de forma idempotente (estilo sshd_config).
core_set_kv() {
    local file="$1" key="$2" value="$3"
    core_read_only && { info "Se estableceria en $file: $key $value"; return 0; }
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=)" "$file" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=).*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >>"$file"
    fi
}

core_pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

# run_live <timeout_secs> <cmd...>
# Ejecuta un comando MOSTRANDO su salida en vivo (verbose), con timeout de
# seguridad para que nunca quede colgado. Devuelve el codigo de salida del cmd.
run_live() {
    local secs="$1"; shift
    local runner=() buf=()
    command -v timeout >/dev/null 2>&1 && runner=(timeout "$secs")
    command -v stdbuf  >/dev/null 2>&1 && buf=(stdbuf -oL -eL)
    "${runner[@]}" "${buf[@]}" "$@" 2>&1 | sed 's/^/    | /'
    return "${PIPESTATUS[0]}"
}
