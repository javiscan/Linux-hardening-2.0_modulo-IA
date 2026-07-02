#!/usr/bin/env bash
# lib/state.sh - ledger de estado: garantiza idempotencia y NO destruccion.
# Registra que control se aplico y con que version. Formato simple (sin jq):
#   clave|version|timestamp

: "${STATE_DIR:=/var/lib/hardening}"
: "${STATE_FILE:=${STATE_DIR}/applied.state}"

state_init() {
    core_read_only && return 0
    [[ -d "$STATE_DIR" ]] || mkdir -p "$STATE_DIR"
    [[ -f "$STATE_FILE" ]] || : >"$STATE_FILE"
}

# ¿Ya se aplico este control (en cualquier version)?
state_is_applied() {
    local key="$1"
    [[ -f "$STATE_FILE" ]] && grep -q "^${key}|" "$STATE_FILE"
}

# ¿Esta aplicado exactamente en esta version? (para detectar deltas)
state_is_version() {
    local key="$1" version="$2"
    [[ -f "$STATE_FILE" ]] && grep -q "^${key}|${version}|" "$STATE_FILE"
}

state_mark_applied() {
    local key="$1" version="${2:-1.0.0}"
    core_read_only && return 0
    state_init
    grep -v "^${key}|" "$STATE_FILE" >"${STATE_FILE}.tmp" 2>/dev/null || true
    echo "${key}|${version}|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
}
