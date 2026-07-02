#!/usr/bin/env bash
# Modulo DNS: resolver confiable (auditoria basica).
MODULE_ID="dns"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="low"; MODULE_CIS="-"

module_describe() { echo "Verifica resolver DNS configurado."; }

module_audit() {
    local ns; ns="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -n1)"
    if [[ -n "$ns" ]]; then
        report_event "$MODULE_ID" "resolver_set" "pass" "low" "nameserver=${ns}"
    else
        report_event "$MODULE_ID" "resolver_set" "fail" "low" "sin nameserver configurado"
    fi
}

module_apply() {
    # No destructivo: solo informa. La eleccion de resolver es interactiva en legacy.
    report_event "$MODULE_ID" "resolver_policy" "skipped" "low" "config de DNS se maneja de forma interactiva (ver legacy)"
}
