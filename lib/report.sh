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
    printf '  %bScore de postura:%b %s/100\n' "$C_WHITE" "$C_RESET" "$score"
    printf '  Controles: %b%s pass%b · %b%s fail%b · %s applied · %s skipped\n' \
        "$C_GREEN" "$R_PASS" "$C_RESET" "$C_RED" "$R_FAIL" "$C_RESET" "$R_APPLIED" "$R_SKIPPED"
    printf '  Criticos/altos abiertos: %b%s%b\n' "$C_RED" "$crit_list" "$C_RESET"
    printf '  Framework v%s | run_id %s | %s\n' "${FRAMEWORK_VERSION}" "${RUN_ID}" "$(date '+%Y-%m-%d %H:%M')"

    if [[ -n "${SUMMARY_FILE:-}" ]]; then
        {
            echo "==== RESUMEN DE SEGURIDAD - ${HOST} (${OS_NAME}) ===="
            echo "Score de postura: ${score}/100"
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
