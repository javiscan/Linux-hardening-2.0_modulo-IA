#!/usr/bin/env bash
# lib/report.sh - emision de eventos JSON estandarizados + scoring.
# Esta es la pieza que habilita la centralizacion (SIEM) y, mas adelante, la IA.

# Contadores globales (persisten en el shell del orquestador)
declare -g R_PASS=0 R_FAIL=0 R_APPLIED=0 R_SKIPPED=0
declare -g R_SCORE_NUM=0 R_SCORE_DEN=0
declare -ga R_CRITICALS=()

# Peso por severidad (para el score de postura)
_report_weight() {
    case "$1" in
        critical) echo 5 ;; high) echo 4 ;; medium) echo 3 ;;
        low) echo 2 ;; *) echo 1 ;;
    esac
}

# Escapa comillas dobles y backslashes para JSON.
_json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# report_event <module> <control_id> <status> <severity> <evidence>
#   status: pass | fail | applied | skipped
report_event() {
    local module="$1" control="$2" status="$3" severity="$4" evidence="$5"
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local w; w="$(_report_weight "$severity")"

    # Contadores + score
    case "$status" in
        pass)    ((R_PASS++));    ((R_SCORE_NUM+=w)); ((R_SCORE_DEN+=w)) ;;
        applied) ((R_APPLIED++)); ((R_SCORE_NUM+=w)); ((R_SCORE_DEN+=w)) ;;
        fail)    ((R_FAIL++));    ((R_SCORE_DEN+=w))
                 [[ "$severity" == "critical" || "$severity" == "high" ]] && R_CRITICALS+=("$control") ;;
        skipped) ((R_SKIPPED++)) ;;
    esac

    # Linea JSON (una por evento)
    local json
    json=$(printf '{"timestamp":"%s","host":"%s","os":"%s","framework_version":"%s","run_id":"%s","module":"%s","control_id":"%s","status":"%s","severity":"%s","evidence":"%s"}' \
        "$ts" "${HOST:-unknown}" "$(_json_escape "${OS_NAME:-unknown}")" "${FRAMEWORK_VERSION:-2.0.0}" \
        "${RUN_ID:-0}" "$module" "$control" "$status" "$severity" "$(_json_escape "$evidence")")

    [[ -n "${EVENTS_FILE:-}" ]] && echo "$json" >>"$EVENTS_FILE"

    # Envio a SIEM / alertas (definido en telemetry.sh; no-op si no esta cargado)
    if declare -F telemetry_send >/dev/null; then telemetry_send "$json" "$status" "$severity" "$control"; fi

    # Salida legible
    local color="$C_CYAN"
    case "$status" in
        pass) color="$C_GREEN" ;; applied) color="$C_GREEN" ;;
        fail) color="$C_RED" ;; skipped) color="$C_WHITE" ;;
    esac
    printf '  %b[%s]%b %-22s %s\n' "$color" "${status^^}" "$C_RESET" "$control" "$evidence"
}

# Score final 0-100 (ponderado por severidad)
report_score() {
    [[ "$R_SCORE_DEN" -eq 0 ]] && { echo 100; return; }
    echo $(( R_SCORE_NUM * 100 / R_SCORE_DEN ))
}

# Genera el resumen legible + JSON por host.
report_summary() {
    local score; score="$(report_score)"
    local crit_list="ninguno"
    [[ ${#R_CRITICALS[@]} -gt 0 ]] && crit_list="${R_CRITICALS[*]}"

    title "RESUMEN DE SEGURIDAD - ${HOST}"
    printf '  %bScore interno (checklist):%b %s/100\n' "$C_WHITE" "$C_RESET" "$score"
    printf '  Controles: %b%s pass%b · %b%s fail%b · %s applied · %s skipped\n' \
        "$C_GREEN" "$R_PASS" "$C_RESET" "$C_RED" "$R_FAIL" "$C_RESET" "$R_APPLIED" "$R_SKIPPED"
    printf '  Criticos/altos abiertos: %b%s%b\n' "$C_RED" "$crit_list" "$C_RESET"
    printf '  Framework v%s | run_id %s | %s\n' "${FRAMEWORK_VERSION}" "${RUN_ID}" "$(date '+%Y-%m-%d %H:%M')"

    if [[ -n "${SUMMARY_FILE:-}" ]]; then
        {
            echo "==== RESUMEN DE SEGURIDAD - ${HOST} (${OS_NAME}) ===="
            echo "Score interno (checklist): ${score}/100"
            echo "Controles: ${R_PASS} pass, ${R_FAIL} fail, ${R_APPLIED} applied, ${R_SKIPPED} skipped"
            echo "Criticos/altos abiertos: ${crit_list}"
            echo "Framework: v${FRAMEWORK_VERSION} | run_id ${RUN_ID} | $(date '+%Y-%m-%d %H:%M')"
        } >"$SUMMARY_FILE"
        # Version JSON del resumen (para maquinas / IA)
        printf '{"host":"%s","score":%s,"pass":%s,"fail":%s,"applied":%s,"skipped":%s,"criticals":"%s","run_id":"%s"}\n' \
            "$HOST" "$score" "$R_PASS" "$R_FAIL" "$R_APPLIED" "$R_SKIPPED" "$(_json_escape "$crit_list")" "$RUN_ID" \
            >"${SUMMARY_FILE%.txt}.json"
    fi
}

# ==============================================================================
# Metricas de postura vs estandares (CIS) y vulnerabilidades (CVE)
# + baseline/delta (punto de inflexion antes/despues)
# ==============================================================================
declare -gA R_METRICS=()

# Valida que un valor sea un porcentaje plausible (0-100)
_pct_ok() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 0 && $1 <= 100 )); }
# Valida entero no negativo (conteos)
_int_ok() { [[ "$1" =~ ^[0-9]+$ ]]; }

# report_metric <nombre> <valor>  (ej: cis_compliance 88 | cve_critical 2)
# GUARDIAN: descarta valores imposibles (evita basura tipo "2026%" de un log).
report_metric() {
    local name="$1" value="$2"
    case "$name" in
        cis_compliance|posture_score|cve_score)
            _pct_ok "$value" || { warn "Metrica '${name}' con valor invalido (${value}); descartada."; return 0; } ;;
        cve_critical|cve_high|lynis_warnings|lynis_suggestions|wazuh_*)
            _int_ok "$value" || return 0 ;;
    esac
    R_METRICS["$name"]="$value"
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local json
    json=$(printf '{"timestamp":"%s","host":"%s","type":"metric","name":"%s","value":"%s","run_id":"%s"}' \
        "$ts" "${HOST:-unknown}" "$name" "$(_json_escape "$value")" "${RUN_ID:-0}")
    [[ -n "${EVENTS_FILE:-}" ]] && echo "$json" >>"$EVENTS_FILE"
    if declare -F telemetry_send >/dev/null; then telemetry_send "$json" "metric" "info" "$name"; fi
}

metrics_save() {
    local f="$1"; mkdir -p "$(dirname "$f")" 2>/dev/null || return 0
    : >"$f"
    local k
    for k in "${!R_METRICS[@]}"; do echo "${k}=${R_METRICS[$k]}" >>"$f"; done
    echo "__timestamp=$(date '+%Y-%m-%d %H:%M')" >>"$f"
}

# metrics_load <archivo> <nombre_array_asociativo>
metrics_load() {
    local f="$1"; local -n _dest="$2"
    [[ -f "$f" ]] || return 1
    local k v
    while IFS='=' read -r k v; do [[ -n "$k" ]] && _dest["$k"]="$v"; done <"$f"
}

baseline_capture() {
    local dir="${STATE_DIR:-/var/lib/hardening}"
    local bf="${dir}/baseline.metrics" lf="${dir}/last.metrics"
    mkdir -p "$dir" 2>/dev/null
    # Auto-reparacion: si el baseline previo tiene un % invalido (dato corrupto), se descarta
    if [[ -f "$bf" ]]; then
        local bc; bc="$(grep -E '^cis_compliance=' "$bf" 2>/dev/null | cut -d= -f2)"
        _pct_ok "$bc" || { rm -f "$bf"; info "Baseline previo invalido (corrupto); se recapturara limpio."; }
    fi
    if [[ ! -f "$bf" && -f "$lf" ]]; then
        cp "$lf" "$bf" 2>/dev/null && info "Baseline capturado: este es tu punto de partida."
    fi
}

baseline_reset() {
    local bf="${STATE_DIR:-/var/lib/hardening}/baseline.metrics"
    rm -f "$bf" 2>/dev/null
    info "Baseline reiniciado. El proximo escaneo sera el nuevo punto de partida."
}

# Postura contra estandares: CIS (config) + CVE (vulnerabilidades)
report_posture() {
    local cis="${R_METRICS[cis_compliance]:-}" est=""
    if [[ -z "$cis" ]]; then
        local den=$((R_PASS + R_FAIL)); cis=100
        [[ $den -gt 0 ]] && cis=$((R_PASS * 100 / den))
        est="  (estimado por checklist; instala OpenSCAP/Lynis o usa Wazuh SCA para % CIS oficial)"
    fi
    R_METRICS[cis_compliance]="$cis"

    local crit="${R_METRICS[cve_critical]:-}" high="${R_METRICS[cve_high]:-}" posture cvescore
    if [[ -n "$crit" || -n "$high" ]]; then
        local c="${crit:-0}" h="${high:-0}"
        local pen=$(( c * 10 + h * 3 )); [[ $pen -gt 100 ]] && pen=100
        cvescore=$(( 100 - pen )); R_METRICS[cve_score]="$cvescore"
        posture=$(( (cis * 6 + cvescore * 4) / 10 ))
    else
        posture="$cis"
    fi
    R_METRICS[posture_score]="$posture"

    title "POSTURA vs ESTANDARES (CIS / CVE)"
    printf '  Cumplimiento CIS: %b%s%%%b%s\n' "$C_WHITE" "$cis" "$C_RESET" "$est"
    if [[ -n "$crit" || -n "$high" ]]; then
        printf '  CVE Criticas: %b%s%b  |  CVE Altas: %s\n' "$C_RED" "${crit:-n/d}" "$C_RESET" "${high:-n/d}"
    else
        printf '  CVE: %bn/d%b  (instala trivy o usa Wazuh Vulnerability Detection)\n' "$C_CYAN" "$C_RESET"
    fi
    printf '  %bScore de postura (vs estandares): %s/100%b\n' "$C_WHITE" "$posture" "$C_RESET"
}

_delta_line() {
    local label="$1" before="$2" after="$3" unit="$4" diff="?" sign=""
    if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then
        diff=$((after - before)); [[ $diff -gt 0 ]] && sign="+"
    fi
    printf '  %-20s %s%s -> %s%s (%b%s%s%b)\n' "$label" "$before" "$unit" "$after" "$unit" \
        "$C_WHITE" "$sign" "$diff" "$C_RESET"
}

# Punto de inflexion: compara baseline (antes) con el estado actual (despues)
report_delta() {
    local bf="${STATE_DIR:-/var/lib/hardening}/baseline.metrics"
    if [[ ! -f "$bf" ]]; then
        info "Sin baseline previo: este escaneo queda como punto de partida."
        return 0
    fi
    declare -A B=(); metrics_load "$bf" B
    # Sanear baseline: descartar porcentajes imposibles (basura de corridas viejas)
    local b_cis="${B[cis_compliance]:-}" b_post="${B[posture_score]:-}"
    _pct_ok "$b_cis"  || b_cis="?"
    _pct_ok "$b_post" || b_post="?"
    title "PUNTO DE INFLEXION (antes -> despues)"
    _delta_line "Cumplimiento CIS" "$b_cis" "${R_METRICS[cis_compliance]:-?}" "%"
    [[ -n "${R_METRICS[cve_critical]:-}" ]] && _delta_line "CVE Criticas" "${B[cve_critical]:-?}" "${R_METRICS[cve_critical]:-?}" ""
    [[ -n "${R_METRICS[cve_high]:-}" ]] && _delta_line "CVE Altas" "${B[cve_high]:-?}" "${R_METRICS[cve_high]:-?}" ""
    _delta_line "Score de postura" "$b_post" "${R_METRICS[posture_score]:-?}" ""
    printf '  Baseline: %s   |   Ahora: %s\n' "${B[__timestamp]:-?}" "$(date '+%Y-%m-%d %H:%M')"
}
