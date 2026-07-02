#!/usr/bin/env bash
# Modulo 0: prerrequisitos (herramientas de seguridad recomendadas).
MODULE_ID="prereqs"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="low"; MODULE_CIS="-"
PREREQ_TOOLS=(auditd suricata fail2ban lynis nmap ufw unattended-upgrades)

module_describe() { echo "Verifica/instala herramientas base: ${PREREQ_TOOLS[*]}"; }

module_audit() {
    local t
    for t in "${PREREQ_TOOLS[@]}"; do
        if core_pkg_installed "$t"; then
            report_event "$MODULE_ID" "tool_${t}" "pass" "low" "instalado"
        else
            report_event "$MODULE_ID" "tool_${t}" "fail" "low" "falta"
        fi
    done
}

module_apply() {
    local missing=() t
    for t in "${PREREQ_TOOLS[@]}"; do core_pkg_installed "$t" || missing+=("$t"); done
    if [[ ${#missing[@]} -eq 0 ]]; then
        report_event "$MODULE_ID" "tools" "pass" "low" "todas instaladas"; return 0
    fi
    if core_confirm "Instalar herramientas faltantes: ${missing[*]}?"; then
        core_run apt-get update -y
        core_run apt-get install -y "${missing[@]}"
        report_event "$MODULE_ID" "tools" "applied" "low" "instaladas: ${missing[*]}"
    else
        report_event "$MODULE_ID" "tools" "skipped" "low" "usuario omitio instalacion"
    fi
}
