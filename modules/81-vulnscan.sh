#!/usr/bin/env bash
# Modulo VulnScan: cuenta CVEs por severidad contra feeds OFICIALES
# (Trivy / debsecan / Wazuh Vulnerability Detection). Mide, no parchea.
MODULE_ID="vulnscan"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="critical"; MODULE_CIS="-"

module_describe() { echo "Vulnerabilidades CVE por severidad (Trivy/debsecan) vs feeds oficiales."; }

module_audit() {
    # 1) Trivy (rapido, feed NVD/vendor)
    if command -v trivy >/dev/null 2>&1; then
        local out crit high
        out="$(trivy rootfs --quiet --scanners vuln --severity CRITICAL,HIGH -f json / 2>/dev/null)"
        crit="$(printf '%s' "$out" | grep -o '"Severity": *"CRITICAL"' | wc -l)"
        high="$(printf '%s' "$out" | grep -o '"Severity": *"HIGH"' | wc -l)"
        report_metric cve_critical "$crit"; report_metric cve_high "$high"
        report_event "$MODULE_ID" "cve_scan" "$([[ $crit -eq 0 ]] && echo pass || echo fail)" \
            "critical" "Trivy: ${crit} criticas, ${high} altas"
        return 0
    fi
    # 2) debsecan (Debian/Ubuntu)
    if command -v debsecan >/dev/null 2>&1; then
        local n; n="$(debsecan --suite "$(lsb_release -cs 2>/dev/null)" 2>/dev/null | wc -l)"
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
