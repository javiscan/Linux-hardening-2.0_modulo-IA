#!/usr/bin/env bash
# lib/backup.sh - copias de seguridad con marca de fecha antes de tocar nada.

: "${BACKUP_DIR:=/root/hardening_backups_$(date +%Y%m%d_%H%M)}"

backup_ensure_dir() {
    core_read_only && return 0
    [[ -d "$BACKUP_DIR" ]] || { mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"; }
}

backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    core_read_only && { info "Se respaldaria: $file"; return 0; }
    backup_ensure_dir
    local dest="${BACKUP_DIR}/$(basename "$file")_backup_$(date +%Y%m%d_%H%M).bak"
    cp -p "$file" "$dest"
    printf '%b[BACKUP]%b %s -> %b%s%b\n' "$C_CYAN" "$C_RESET" "$file" "$C_CYAN" "$dest" "$C_RESET"
}
