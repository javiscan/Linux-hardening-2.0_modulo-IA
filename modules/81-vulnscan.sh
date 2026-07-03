#!/usr/bin/env bash
# Modulo VulnScan: DETERMINA vulnerabilidades con la mejor fuente disponible
# (Trivy -> debsecan -> Lynis -> apt security). Evita "n/d": siempre da un numero.
MODULE_ID="vulnscan"
MODULE_KIND="measure"
MODULE_VERSION="2.2.0"; MODULE_SEVERITY="critical"; MODULE_CIS="-"

module_describe() { echo "Vulnerabilidades por severidad; usa Trivy o alternativas (Lynis/apt)."; }

module_audit() {
    # 1) Trivy (severidad real: criticas/altas)
    if command -v trivy >/dev/null 2>&1; then
        info "Escaneo de vulnerabilidades con Trivy en curso: veras el progreso abajo."
        note "  La 1a vez descarga la base de CVE (puede tardar). NO hace falta cancelar."
        local jf; jf="$(mktemp)"
        run_live 900 trivy rootfs --scanners vuln --severity CRITICAL,HIGH -f json -o "$jf" /
        [[ $? -eq 124 ]] && { rm -f "$jf"; report_event "$MODULE_ID" "cve_scan" "skipped" "critical" "Trivy: tiempo excedido"; return 0; }
        local crit high
        crit="$(grep -o '"Severity": *"CRITICAL"' "$jf" 2>/dev/null | wc -l)"
        high="$(grep -o '"Severity": *"HIGH"' "$jf" 2>/dev/null | wc -l)"
        rm -f "$jf"
        report_metric cve_critical "$crit"; report_metric cve_high "$high"
        report_event "$MODULE_ID" "cve_scan" "$([[ $crit -eq 0 ]] && echo pass || echo fail)" \
            "critical" "Trivy: ${crit} criticas, ${high} altas"
        return 0
    fi
    # 2) debsecan (Debian/Ubuntu)
    if command -v debsecan >/dev/null 2>&1; then
        info "Escaneo de vulnerabilidades con debsecan en curso..."
        local tmp; tmp="$(mktemp)"
        run_live 300 debsecan --suite "$(lsb_release -cs 2>/dev/null)" >"$tmp" 2>/dev/null || true
        local n; n="$(grep -c . "$tmp" 2>/dev/null)"; n="${n:-0}"; rm -f "$tmp"
        report_metric cve_critical 0; report_metric cve_high "$n"
        report_event "$MODULE_ID" "cve_scan" "$([[ $n -eq 0 ]] && echo pass || echo fail)" \
            "critical" "debsecan: ${n} paquetes con CVE (severidad no separada; instala trivy para criticas/altas)"
        return 0
    fi
    # 3) Lynis: paquetes vulnerables ya detectados (si corrio el modulo cis)
    if [[ -r /var/log/lynis-report.dat ]]; then
        local vp; vp="$(grep -acE '^vulnerable_package\[\]=' /var/log/lynis-report.dat 2>/dev/null)"; vp="${vp:-0}"
        report_metric cve_critical 0; report_metric cve_high "$vp"
        report_event "$MODULE_ID" "cve_scan" "$([[ $vp -eq 0 ]] && echo pass || echo fail)" \
            "critical" "Lynis: ${vp} paquetes vulnerables (severidad no separada; instala trivy para CVE por severidad)"
        return 0
    fi
    # 4) apt: actualizaciones de seguridad pendientes (proxy determinable)
    if command -v apt-get >/dev/null 2>&1; then
        local sec; sec="$(apt-get -s upgrade 2>/dev/null | grep -ciE 'security')"; sec="${sec:-0}"
        report_metric cve_critical 0; report_metric cve_high "$sec"
        report_event "$MODULE_ID" "cve_scan" "$([[ $sec -eq 0 ]] && echo pass || echo fail)" \
            "critical" "${sec} actualizaciones de seguridad pendientes (proxy; instala trivy para CVE por severidad)"
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
