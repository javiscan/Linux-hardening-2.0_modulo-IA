#!/usr/bin/env bash
# Modulo CIS: mide el % de cumplimiento con herramientas OFICIALES (OpenSCAP/Lynis),
# muestra el analisis EN VIVO y SURFACEA los hallazgos (warnings/sugerencias).
MODULE_ID="cis"; MODULE_VERSION="2.2.0"; MODULE_SEVERITY="high"; MODULE_CIS="-"
MODULE_KIND="measure"

module_describe() { echo "Cumplimiento CIS oficial (OpenSCAP/Lynis) con hallazgos y progreso en vivo."; }

# --- Lynis: parseo robusto desde lynis-report.dat (dato limpio, sin timestamps) ---
_cis_lynis_parse() {
    local rep="/var/log/lynis-report.dat" log="/var/log/lynis.log"
    local idx warns suggs
    idx="$(grep -aE '^hardening_index=' "$rep" 2>/dev/null | tail -n1 | cut -d= -f2)"
    # Fallback: leer del log pero anclando al texto (evita agarrar el año del timestamp)
    [[ -z "$idx" ]] && idx="$(grep -a 'Hardening index' "$log" 2>/dev/null | tail -n1 | sed -E 's/.*Hardening index[^0-9]*([0-9]+).*/\1/')"
    warns="$(grep -acE '^warning\[\]=' "$rep" 2>/dev/null)"; warns="${warns:-0}"
    suggs="$(grep -acE '^suggestion\[\]=' "$rep" 2>/dev/null)"; suggs="${suggs:-0}"

    [[ -z "$idx" ]] && { report_event "$MODULE_ID" "cis_compliance" "skipped" "high" "Lynis no reporto indice (revisa /var/log/lynis.log)"; return 0; }

    report_metric cis_compliance "$idx"
    report_metric lynis_warnings "$warns"
    report_metric lynis_suggestions "$suggs"
    report_event "$MODULE_ID" "cis_compliance" "$([[ $idx -ge 80 ]] && echo pass || echo fail)" \
        "high" "Lynis hardening index: ${idx}/100  (warnings: ${warns}, sugerencias: ${suggs})"

    # WARNINGS = problemas concretos -> cada uno como hallazgo (severity high)
    local line tid txt
    while IFS= read -r line; do
        tid="$(printf '%s' "$line" | sed -E 's/^warning\[\]=//' | cut -d'|' -f1)"
        txt="$(printf '%s' "$line" | cut -d'|' -f2)"
        [[ -n "$txt" ]] && report_event "$MODULE_ID" "lynis_${tid}" "fail" "high" "$txt"
    done < <(grep -aE '^warning\[\]=' "$rep" 2>/dev/null)

    # SUGERENCIAS = mejoras recomendadas -> se guardan completas para el informe
    if [[ "$suggs" -gt 0 && -n "${SUMMARY_FILE:-}" ]]; then
        local sf; sf="$(dirname "$SUMMARY_FILE")/lynis_sugerencias_${RUN_ID:-0}.txt"
        grep -aE '^suggestion\[\]=' "$rep" 2>/dev/null \
            | sed -E 's/^suggestion\[\]=//; s/\|/  |  /g' > "$sf"
        info "Sugerencias de Lynis (${suggs}) guardadas en: ${sf}"
    fi
    return 0
}

module_audit() {
    # 1) OpenSCAP + SCAP Security Guide (perfil CIS)
    if command -v oscap >/dev/null 2>&1; then
        local ds; ds="$(ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml 2>/dev/null | head -n1)"
        if [[ -n "$ds" ]]; then
            info "Escaneo CIS con OpenSCAP en curso: veras cada control a medida que se evalua."
            note "  Puede tardar 2-5 min. NO hace falta cancelar; el progreso aparece abajo."
            local tmp; tmp="$(mktemp)"
            run_live 900 oscap xccdf eval --profile 'cis' --progress --results "$tmp" "$ds"
            [[ $? -eq 124 ]] && { rm -f "$tmp"; report_event "$MODULE_ID" "cis_compliance" "skipped" "high" "OpenSCAP: tiempo excedido"; return 0; }
            local pass fail total pct
            pass="$(grep -c '<result>pass</result>' "$tmp" 2>/dev/null)"; pass="${pass:-0}"
            fail="$(grep -c '<result>fail</result>' "$tmp" 2>/dev/null)"; fail="${fail:-0}"
            rm -f "$tmp"
            total=$((pass + fail)); pct=0; [[ $total -gt 0 ]] && pct=$((pass * 100 / total))
            report_metric cis_compliance "$pct"
            report_event "$MODULE_ID" "cis_compliance" "$([[ $pct -ge 80 ]] && echo pass || echo fail)" \
                "high" "OpenSCAP CIS: ${pct}% (${pass} pass / ${fail} fail)"
            return 0
        fi
    fi
    # 2) Lynis (indice de hardening + warnings + sugerencias)
    if command -v lynis >/dev/null 2>&1; then
        info "Escaneo CIS con Lynis en curso: veras cada seccion que evalua."
        note "  Puede tardar 1-2 min. NO hace falta cancelar; el progreso aparece abajo."
        run_live 600 lynis audit system --quick --no-colors
        [[ $? -eq 124 ]] && { report_event "$MODULE_ID" "cis_compliance" "skipped" "high" "Lynis: tiempo excedido"; return 0; }
        _cis_lynis_parse
        return 0
    fi
    report_event "$MODULE_ID" "cis_tooling" "skipped" "high" \
        "Instala 'openscap-scanner + ssg' o 'lynis', o usa Wazuh SCA para el % CIS oficial"
}

module_apply() { module_audit; }   # es medicion: no destructivo
