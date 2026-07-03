#!/usr/bin/env bash
# Modulo CIS: mide el % de cumplimiento CIS con herramientas OFICIALES
# (OpenSCAP + SSG, o Lynis como referencia). No inventa la base: la consulta.
MODULE_ID="cis"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="high"; MODULE_CIS="-"

module_describe() { echo "Cumplimiento CIS oficial (OpenSCAP/Lynis) — comparativa vs estandar."; }

module_audit() {
    # 1) OpenSCAP + SCAP Security Guide (perfil CIS)
    if command -v oscap >/dev/null 2>&1; then
        local ds; ds="$(ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml 2>/dev/null | head -n1)"
        if [[ -n "$ds" ]]; then
            local tmp; tmp="$(mktemp)"
            oscap xccdf eval --profile 'cis' --results "$tmp" "$ds" >/dev/null 2>&1 || true
            local pass fail total pct
            pass="$(grep -c '<result>pass</result>' "$tmp" 2>/dev/null || echo 0)"
            fail="$(grep -c '<result>fail</result>' "$tmp" 2>/dev/null || echo 0)"
            rm -f "$tmp"
            total=$((pass + fail)); pct=0; [[ $total -gt 0 ]] && pct=$((pass * 100 / total))
            report_metric cis_compliance "$pct"
            report_event "$MODULE_ID" "cis_compliance" "$([[ $pct -ge 80 ]] && echo pass || echo fail)" \
                "high" "OpenSCAP CIS: ${pct}% (${pass}/${total} controles)"
            return 0
        fi
    fi
    # 2) Lynis (indice de hardening, referencia rapida)
    if command -v lynis >/dev/null 2>&1; then
        lynis audit system --quick --quiet >/dev/null 2>&1 || true
        local idx; idx="$(grep -a 'Hardening index' /var/log/lynis.log 2>/dev/null | tail -n1 | grep -oE '[0-9]+' | head -n1)"
        if [[ -n "$idx" ]]; then
            report_metric cis_compliance "$idx"
            report_event "$MODULE_ID" "cis_compliance" "$([[ $idx -ge 80 ]] && echo pass || echo fail)" \
                "high" "Lynis hardening index: ${idx}/100"
            return 0
        fi
    fi
    report_event "$MODULE_ID" "cis_tooling" "skipped" "high" \
        "Instala 'openscap-scanner + ssg' o 'lynis', o usa Wazuh SCA para el % CIS oficial"
}

module_apply() { module_audit; }   # es medicion: no destructivo
