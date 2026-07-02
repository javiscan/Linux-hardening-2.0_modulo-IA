#!/usr/bin/env bash
# Modulo Red: firewall UFW deny-all con proteccion anti-bloqueo de SSH.
MODULE_ID="network"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="high"; MODULE_CIS="3.5"

module_describe() { echo "UFW deny-all + rate-limit SSH (anti-bloqueo)."; }

_ssh_port() { sshd -T 2>/dev/null | awk '/^port / {print $2; exit}'; }

module_audit() {
    if command -v ufw >/dev/null 2>&1; then
        local st; st="$(ufw status 2>/dev/null | awk '/^Status:/ {print $2}')"
        [[ "$st" == "active" ]] && report_event "$MODULE_ID" "ufw_enabled" "pass" "high" "UFW activo" \
            || report_event "$MODULE_ID" "ufw_enabled" "fail" "high" "UFW inactivo"
    else
        report_event "$MODULE_ID" "ufw_installed" "fail" "high" "UFW no instalado"
    fi
}

module_apply() {
    command -v ufw >/dev/null 2>&1 || { core_confirm "Instalar UFW?" && core_run apt-get install -y ufw || \
        { report_event "$MODULE_ID" "ufw_installed" "skipped" "high" "no instalado"; return 0; }; }
    local port; port="$(_ssh_port)"; port="${port:-22}"
    # ANTI-BLOQUEO: permitir SSH ANTES del deny-all
    core_run ufw allow "${port}/tcp"
    core_run ufw limit "${port}/tcp"
    core_run ufw default deny incoming
    core_run ufw default allow outgoing
    if ! core_read_only; then ufw --force enable >/dev/null 2>&1 || true; fi
    state_mark_applied "${MODULE_ID}:ufw" "$MODULE_VERSION"
    report_event "$MODULE_ID" "ufw_enabled" "applied" "high" "deny-all con SSH ${port} permitido y limitado"
    warn "Verifica el acceso SSH en otra terminal antes de cerrar la sesion."
}
