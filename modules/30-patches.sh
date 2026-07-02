#!/usr/bin/env bash
# Modulo Parches: actualizaciones de seguridad automaticas + inventario.
MODULE_ID="patches"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="high"; MODULE_CIS="1.9"

module_describe() { echo "unattended-upgrades + inventario del sistema."; }

module_audit() {
    local pending; pending="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
    [[ "$pending" -eq 0 ]] && report_event "$MODULE_ID" "pending_updates" "pass" "high" "sin actualizaciones pendientes" \
        || report_event "$MODULE_ID" "pending_updates" "fail" "high" "${pending} actualizaciones pendientes"
    core_pkg_installed unattended-upgrades \
        && report_event "$MODULE_ID" "auto_updates" "pass" "medium" "unattended-upgrades presente" \
        || report_event "$MODULE_ID" "auto_updates" "fail" "medium" "sin parches automaticos"
}

module_apply() {
    if ! core_pkg_installed unattended-upgrades; then
        core_confirm "Instalar unattended-upgrades?" && core_run apt-get install -y unattended-upgrades
    fi
    if ! core_read_only && core_pkg_installed unattended-upgrades; then
        cat >/etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
    fi
    state_mark_applied "${MODULE_ID}:auto" "$MODULE_VERSION"
    report_event "$MODULE_ID" "auto_updates" "applied" "medium" "parches de seguridad automaticos habilitados"
}
