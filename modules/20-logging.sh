#!/usr/bin/env bash
# Modulo Logging/Auditoria: auditd con reglas base.
MODULE_ID="logging"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="medium"; MODULE_CIS="4.1"
RULES="/etc/audit/rules.d/hardening.rules"

module_describe() { echo "auditd + reglas CIS + retencion de logs."; }

module_audit() {
    if core_pkg_installed auditd; then
        local active; active="$(systemctl is-active auditd 2>/dev/null)"
        [[ "$active" == "active" ]] && report_event "$MODULE_ID" "auditd_running" "pass" "medium" "auditd activo" \
            || report_event "$MODULE_ID" "auditd_running" "fail" "medium" "auditd inactivo"
    else
        report_event "$MODULE_ID" "auditd_installed" "fail" "medium" "auditd no instalado"
    fi
}

module_apply() {
    if ! core_pkg_installed auditd; then
        core_confirm "Instalar auditd?" && core_run apt-get install -y auditd || \
            { report_event "$MODULE_ID" "auditd_installed" "skipped" "medium" "no instalado"; return 0; }
    fi
    if ! state_is_version "${MODULE_ID}:rules" "$MODULE_VERSION"; then
        if ! core_read_only; then
            cat >"$RULES" <<'RULES'
-w /etc/passwd -p wa -k identidad
-w /etc/shadow -p wa -k identidad
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k ssh
-a always,exit -F arch=b64 -S init_module -S delete_module -k modulos
RULES
            augenrules --load 2>/dev/null || true
            systemctl enable --now auditd 2>/dev/null || true
        else
            info "Se cargarian reglas auditd en ${RULES}"
        fi
        state_mark_applied "${MODULE_ID}:rules" "$MODULE_VERSION"
        report_event "$MODULE_ID" "auditd_rules" "applied" "medium" "reglas CIS base cargadas"
    else
        report_event "$MODULE_ID" "auditd_rules" "skipped" "medium" "ya aplicado"
    fi
}
