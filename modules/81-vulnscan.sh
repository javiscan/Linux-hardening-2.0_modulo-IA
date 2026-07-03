#!/usr/bin/env bash
# Modulo VulnScan: cuenta CVEs por severidad contra feeds OFICIALES
# (Trivy / debsecan). Muestra el progreso EN VIVO. Mide, no parchea.
MODULE_ID="vulnscan"; MODULE_VERSION="2.1.0"; MODULE_SEVERITY="critical"; MODULE_CIS="-"

module_describe() { echo "Vulnerabilidades CVE por severidad (Trivy/debsecan) — con progreso en vivo."; }

module_audit() {
    # 1) Trivy (progreso a stderr; JSON a archivo para contar)
    if command -v trivy >/dev/null 2>&1; then
        info "Escaneo de vulnerabilidades con Trivy en curso: veras el progreso abajo."
        note "  La 1a vez descarga la base de CVE (puede tardar). NO hace falta cancelar."
        local jf; jf="$(mktemp)"
        run_live 900 trivy rootfs --scanners vuln --severity CRITICAL,HIGH -f json -o "$jf" /
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            rm -f "$jf"
            report_event "$MODULE_ID" "cve_scan" "skipped" "critical" "Trivy: tiempo excedido (scan no completado)"
            return 0
        fi
        local crit high
        crit="$(grep -o '"Severity": *"CRITICAL"' "$jf" 2>/dev/null | wc -l)"
        high="$(grep -o '"Severity": *"HIGH"' "$jf" 2>/dev/null | wc -l)"
        rm -f "$jf"
        report_metric cve_critical "$crit"; report_metric cve_high "$high"
        report_event "$MODULE_ID" "cve_scan" "$([[ $crit -eq 0 ]] && echo pass || echo fail)" \
            "critical" "Trivy: ${crit} criticas, ${high} altas"
        return 0
    fi
    # 2) debsecan
    if command -v debsecan >/dev/null 2>&1; then
        info "Escaneo de vulnerabilidades con debsecan en curso..."
        local tmp; tmp="$(mktemp)"
        run_live 300 debsecan --suite "$(lsb_release -cs 2>/dev/null)" >"$tmp" 2>/dev/null || true
        local n; n="$(grep -c . "$tmp" 2>/dev/null || echo 0)"; rm -f "$tmp"
        report_metric cve_critical "$n"
        report_event "$MODULE_ID" "cve_scan" "$([[ $n -eq 0 ]] && echo pass || echo fail)" \
            "critical" "debsecan: ${n} CVEs detectadas"
        return 0
    fi
    report_event "$MODULE_ID" "cve_tooling" "skipped" "critical" \
        "Instala 'trivy' o 'debsecan', o usa Wazuh Vulnerability Detection"
}

module_apply() {
    module_audit
    report_event "$MODULE_ID" "cve_remediation" "skipped" "high" \
        "Cerrar CVEs = parchear: usa el modulo 'patches' (apt upgrade / unattended-upgrades)"
}
