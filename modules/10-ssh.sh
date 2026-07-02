#!/usr/bin/env bash
# Modulo SSH: endurecimiento de la puerta de entrada remota.
MODULE_ID="ssh"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="high"; MODULE_CIS="5.2"
SSHD="/etc/ssh/sshd_config"

module_describe() { echo "Hardening de SSH: root off, auth por clave, MaxAuthTries."; }

_ssh_effective() { sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1)==k {print $2}'; }

module_audit() {
    [[ -f "$SSHD" ]] || { report_event "$MODULE_ID" "ssh_present" "skipped" "high" "sshd no instalado"; return 0; }
    local root pass; root="$(_ssh_effective permitrootlogin)"; pass="$(_ssh_effective passwordauthentication)"
    [[ "$root" == "no" ]] && report_event "$MODULE_ID" "ssh_root_login" "pass" "high" "root deshabilitado" \
        || report_event "$MODULE_ID" "ssh_root_login" "fail" "high" "PermitRootLogin=${root:-?}"
    [[ "$pass" == "no" ]] && report_event "$MODULE_ID" "ssh_password_auth" "pass" "medium" "solo clave publica" \
        || report_event "$MODULE_ID" "ssh_password_auth" "fail" "medium" "PasswordAuthentication=${pass:-?}"
}

module_apply() {
    [[ -f "$SSHD" ]] || { report_event "$MODULE_ID" "ssh_present" "skipped" "high" "sshd no instalado"; return 0; }
    if ! state_is_version "${MODULE_ID}:root_login" "$MODULE_VERSION"; then
        backup_file "$SSHD"
        core_set_kv "$SSHD" "PermitRootLogin" "no"
        core_set_kv "$SSHD" "MaxAuthTries" "3"
        core_set_kv "$SSHD" "X11Forwarding" "no"
        if ! core_read_only; then sshd -t 2>/dev/null && systemctl reload ssh 2>/dev/null; fi
        state_mark_applied "${MODULE_ID}:root_login" "$MODULE_VERSION"
        report_event "$MODULE_ID" "ssh_root_login" "applied" "high" "root off + MaxAuthTries=3"
    else
        report_event "$MODULE_ID" "ssh_root_login" "skipped" "high" "ya aplicado (v${MODULE_VERSION})"
    fi
    warn "Verifica una nueva conexion SSH en otra terminal antes de cerrar esta."
}
