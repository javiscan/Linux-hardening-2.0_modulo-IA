#!/usr/bin/env bash
# lib/report_full.sh - Reporte CONSOLIDADO para el usuario final.
# Genera un informe unico (Markdown + HTML) con: postura, plan de accion
# (que hacer en el endpoint), mejoras aplicadas, modulos afectados y delta.
# Solo lee datos; no modifica el sistema.

# Consejo de remediacion por control (que modulo/accion resuelve cada hallazgo)
_rf_advice() {
    case "$1" in
        ssh_root_login)                  echo "Modulo 'ssh': deshabilitar login de root (PermitRootLogin no)." ;;
        ssh_password_auth)               echo "Modulo 'ssh': forzar clave publica (PasswordAuthentication no)." ;;
        ufw_enabled|ufw_installed)       echo "Modulo 'network': activar firewall UFW deny-all (permite SSH antes)." ;;
        pending_updates|auto_updates)    echo "Modulo 'patches': apt upgrade + unattended-upgrades." ;;
        auditd_installed|auditd_running|auditd_rules) echo "Modulo 'logging': instalar/activar auditd con reglas CIS." ;;
        edr_present)                     echo "Modulo 'edr': desplegar agente Wazuh/EDR en el endpoint." ;;
        cve_scan|cve_tooling)            echo "Modulo 'patches': parchear paquetes con CVE (o instalar Trivy para detalle)." ;;
        cis_compliance|cis_tooling)      echo "Aplicar modulos de hardening; revisar Lynis/OpenSCAP para subir el % CIS." ;;
        resolver_set)                    echo "Modulo 'dns': configurar un resolver DNS confiable." ;;
        aslr|ip_forward|sysctl_cis)      echo "Modulo 'os': aplicar parametros sysctl CIS." ;;
        lynis_*)                         echo "Detalle Lynis: 'lynis show details ${1#lynis_}'." ;;
        tool_*)                          echo "Modulo 'prereqs': instalar la herramienta de seguridad faltante." ;;
        *)                               echo "Revisar el modulo correspondiente y remediar." ;;
    esac
}

_rf_metric() { grep -E "^$1=" "$2" 2>/dev/null | head -n1 | cut -d= -f2-; }

# Extrae campo de un evento JSON (una linea)
_rf_field() { sed -E "s/.*\"$2\":\"([^\"]*)\".*/\1/" <<<"$1"; }

generate_full_report() {
    local dir="${REPORT_DIR:-.}"
    local rid="${RUN_ID:-$(date +%H%M%S)}"
    local md="${dir}/reporte_completo_${rid}.md"
    local html="${dir}/reporte_completo_${rid}.html"
    local st="${STATE_DIR:-/var/lib/hardening}"
    local ev; ev="$(ls -t "$dir"/events_*.jsonl 2>/dev/null | head -n1)"
    local metrics="${st}/last.metrics" baseline="${st}/baseline.metrics" ledger="${st}/applied.state"
    local sugg; sugg="$(ls -t "$dir"/lynis_sugerencias_*.txt 2>/dev/null | head -n1)"

    # --- Metricas (saneadas) ---
    local cis crit high post
    cis="$(_rf_metric cis_compliance "$metrics")"; _pct_ok "$cis" || cis="n/d"
    post="$(_rf_metric posture_score "$metrics")"; _pct_ok "$post" || post="n/d"
    crit="$(_rf_metric cve_critical "$metrics")"; [[ "$crit" =~ ^[0-9]+$ ]] || crit="n/d"
    high="$(_rf_metric cve_high "$metrics")"; [[ "$high" =~ ^[0-9]+$ ]] || high="n/d"
    local b_cis b_post
    b_cis="$(_rf_metric cis_compliance "$baseline")"; _pct_ok "$b_cis" || b_cis="?"
    b_post="$(_rf_metric posture_score "$baseline")"; _pct_ok "$b_post" || b_post="?"

    # --- Recolectar hallazgos por modulo ---
    local mods="" line m st_ status ctrl sev evi
    declare -A M_PASS=() M_FAIL=() M_APPLIED=()
    declare -a ACTIONS=() APPLIEDLIST=()
    if [[ -n "$ev" ]]; then
        while IFS= read -r line; do
            m="$(_rf_field "$line" module)"; status="$(_rf_field "$line" status)"
            ctrl="$(_rf_field "$line" control_id)"; sev="$(_rf_field "$line" severity)"; evi="$(_rf_field "$line" evidence)"
            case "$status" in
                pass) M_PASS["$m"]=$(( ${M_PASS["$m"]:-0} + 1 )) ;;
                fail) M_FAIL["$m"]=$(( ${M_FAIL["$m"]:-0} + 1 ))
                      ACTIONS+=("${sev}|${m}|${ctrl}|${evi}|$(_rf_advice "$ctrl")") ;;
                applied) M_APPLIED["$m"]=$(( ${M_APPLIED["$m"]:-0} + 1 ))
                      APPLIEDLIST+=("${m}|${ctrl}|${evi}") ;;
            esac
            [[ "$mods" != *"|$m|"* ]] && mods="${mods}|$m|"
        done < <(cat "$ev")
    fi

    # --- Mejoras aplicadas historicamente (ledger) ---
    declare -a LEDGER=()
    if [[ -f "$ledger" ]]; then
        while IFS='|' read -r k ver ts; do
            [[ -n "$k" ]] && LEDGER+=("${k}|${ver}|${ts}")
        done < "$ledger"
    fi

    # ============================ MARKDOWN ============================
    {
        echo "# Reporte de Hardening - ${HOST:-endpoint}"
        echo "_Generado: $(date '+%Y-%m-%d %H:%M') | Sistema: ${OS_NAME:-Linux} | run_id: ${rid}_"
        echo
        echo "## 1. Postura de seguridad (vs estandares)"
        echo
        echo "| Metrica | Valor |"
        echo "|---|---|"
        echo "| Score de postura | **${post}/100** |"
        echo "| Cumplimiento CIS | ${cis}% |"
        echo "| CVE criticas | ${crit} |"
        echo "| CVE altas | ${high} |"
        echo
        echo "## 2. Punto de inflexion (antes -> despues)"
        echo
        echo "| Metrica | Antes | Ahora |"
        echo "|---|---|---|"
        echo "| Cumplimiento CIS | ${b_cis}% | ${cis}% |"
        echo "| Score de postura | ${b_post} | ${post} |"
        echo
        echo "## 3. Que tenes que hacer en tu endpoint (plan de accion)"
        echo
        if [[ ${#ACTIONS[@]} -gt 0 ]]; then
            printf '%s\n' "${ACTIONS[@]}" | sort | while IFS='|' read -r sev m ctrl evi adv; do
                echo "- **[${sev}] ${ctrl}** (modulo ${m}) — ${evi}"
                echo "  - Accion: ${adv}"
            done
        else
            echo "- Sin acciones pendientes. 👍"
        fi
        echo
        echo "## 4. Mejoras aplicadas en esta sesion"
        echo
        if [[ ${#APPLIEDLIST[@]} -gt 0 ]]; then
            printf '%s\n' "${APPLIEDLIST[@]}" | while IFS='|' read -r m ctrl evi; do
                echo "- ${m} / ${ctrl}: ${evi}"
            done
        else
            echo "- No se aplicaron cambios en esta sesion (modo auditoria o nada pendiente)."
        fi
        echo
        echo "## 5. Estado por modulo"
        echo
        echo "| Modulo | Pass | Fail | Aplicados |"
        echo "|---|---|---|---|"
        local mm
        for mm in $(printf '%s' "$mods" | tr '|' '\n' | grep -v '^$' | sort -u); do
            echo "| ${mm} | ${M_PASS[$mm]:-0} | ${M_FAIL[$mm]:-0} | ${M_APPLIED[$mm]:-0} |"
        done
        echo
        echo "## 6. Historial de mejoras (ledger)"
        echo
        if [[ ${#LEDGER[@]} -gt 0 ]]; then
            printf '%s\n' "${LEDGER[@]}" | while IFS='|' read -r k ver ts; do
                echo "- ${k} (v${ver}) — ${ts}"
            done
        else
            echo "- Todavia no hay remediaciones registradas."
        fi
        if [[ -n "$sugg" ]]; then
            echo
            echo "## 7. Sugerencias de Lynis"
            echo '```'
            head -n 25 "$sugg"
            echo '```'
        fi
    } > "$md"

    # ============================== HTML ==============================
    local score_color="#c0392b"
    [[ "$post" =~ ^[0-9]+$ ]] && { (( post >= 80 )) && score_color="#27ae60"; (( post >= 60 && post < 80 )) && score_color="#e67e22"; }
    {
        cat <<HDR
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte Hardening - ${HOST:-endpoint}</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0f1720;color:#e6edf3;margin:0;padding:24px;}
 .wrap{max-width:960px;margin:0 auto;}
 h1{margin:0 0 4px;} .sub{color:#8aa0b3;font-size:14px;margin-bottom:20px;}
 h2{border-bottom:1px solid #24303c;padding-bottom:6px;margin-top:28px;color:#7fd7ff;}
 .score{font-size:44px;font-weight:800;color:${score_color};}
 table{border-collapse:collapse;width:100%;margin:8px 0;}
 th,td{border:1px solid #24303c;padding:8px 10px;text-align:left;font-size:14px;}
 th{background:#16212c;}
 .crit{color:#ff6b6b;font-weight:700;} .high{color:#ffa94d;} .ok{color:#51cf66;}
 li{margin:4px 0;} code,pre{background:#0b1118;border:1px solid #24303c;border-radius:6px;}
 pre{padding:12px;overflow:auto;font-size:12px;} .card{background:#131c26;border:1px solid #24303c;border-radius:10px;padding:16px;margin:12px 0;}
</style></head><body><div class="wrap">
<h1>Reporte de Hardening — ${HOST:-endpoint}</h1>
<div class="sub">Generado: $(date '+%Y-%m-%d %H:%M') · Sistema: ${OS_NAME:-Linux} · run_id: ${rid}</div>
<div class="card"><div>Score de postura (vs estandares)</div><div class="score">${post}/100</div>
<div>Cumplimiento CIS: <b>${cis}%</b> · CVE criticas: <b class="crit">${crit}</b> · CVE altas: <b class="high">${high}</b></div>
<div class="sub">Punto de inflexion — CIS ${b_cis}% → ${cis}% · Postura ${b_post} → ${post}</div></div>
<h2>Que tenes que hacer en tu endpoint</h2><ul>
HDR
        if [[ ${#ACTIONS[@]} -gt 0 ]]; then
            printf '%s\n' "${ACTIONS[@]}" | sort | while IFS='|' read -r sev m ctrl evi adv; do
                local cls="high"; [[ "$sev" == "critical" ]] && cls="crit"
                echo "<li><span class=\"${cls}\">[${sev}]</span> <b>${ctrl}</b> (modulo ${m}) — ${evi}<br><i>Accion:</i> ${adv}</li>"
            done
        else
            echo "<li class=\"ok\">Sin acciones pendientes.</li>"
        fi
        echo "</ul><h2>Mejoras aplicadas en esta sesion</h2><ul>"
        if [[ ${#APPLIEDLIST[@]} -gt 0 ]]; then
            printf '%s\n' "${APPLIEDLIST[@]}" | while IFS='|' read -r m ctrl evi; do
                echo "<li class=\"ok\">${m} / ${ctrl}: ${evi}</li>"
            done
        else
            echo "<li>No se aplicaron cambios en esta sesion.</li>"
        fi
        echo "</ul><h2>Estado por modulo</h2><table><tr><th>Modulo</th><th>Pass</th><th>Fail</th><th>Aplicados</th></tr>"
        local mm
        for mm in $(printf '%s' "$mods" | tr '|' '\n' | grep -v '^$' | sort -u); do
            echo "<tr><td>${mm}</td><td class=\"ok\">${M_PASS[$mm]:-0}</td><td class=\"crit\">${M_FAIL[$mm]:-0}</td><td>${M_APPLIED[$mm]:-0}</td></tr>"
        done
        echo "</table><h2>Historial de mejoras (ledger)</h2><ul>"
        if [[ ${#LEDGER[@]} -gt 0 ]]; then
            printf '%s\n' "${LEDGER[@]}" | while IFS='|' read -r k ver ts; do echo "<li>${k} (v${ver}) — ${ts}</li>"; done
        else
            echo "<li>Todavia no hay remediaciones registradas.</li>"
        fi
        echo "</ul>"
        if [[ -n "$sugg" ]]; then
            echo "<h2>Sugerencias de Lynis</h2><pre>$(head -n 25 "$sugg" | sed 's/</\&lt;/g')</pre>"
        fi
        echo "</div></body></html>"
    } > "$html"

    title "REPORTE CONSOLIDADO GENERADO"
    ok "Markdown: ${md}"
    ok "HTML (abrir en navegador): ${html}"
}
