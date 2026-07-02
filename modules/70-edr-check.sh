#!/usr/bin/env bash
# Modulo EDR/Agente: verifica que el endpoint tenga un agente de seguridad/EDR.
# No instala EDRs de terceros; comprueba presencia y estado (auditoria de postura).
MODULE_ID="edr"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="high"; MODULE_CIS="-"

# Agentes/EDR conocidos:  "binario_o_servicio:Nombre legible"
EDR_CANDIDATES=(
    "wazuh-agentd:Wazuh Agent"
    "filebeat:Elastic Filebeat"
    "osqueryd:osquery"
    "falcon-sensor:CrowdStrike Falcon"
    "mdatp:Microsoft Defender for Endpoint"
    "sentinelctl:SentinelOne"
    "auditd:Linux auditd"
    "suricata:Suricata IDS"
    "clamd:ClamAV"
)

module_describe() { echo "Verifica presencia de EDR/agente de seguridad en el endpoint."; }

_edr_present() {
    local bin="$1"
    command -v "$bin" >/dev/null 2>&1 && return 0
    systemctl list-unit-files 2>/dev/null | grep -q "^${bin}" && return 0
    pgrep -x "$bin" >/dev/null 2>&1 && return 0
    return 1
}

module_audit() {
    local found=() entry bin name
    for entry in "${EDR_CANDIDATES[@]}"; do
        bin="${entry%%:*}"; name="${entry#*:}"
        _edr_present "$bin" && found+=("$name")
    done
    if [[ ${#found[@]} -gt 0 ]]; then
        report_event "$MODULE_ID" "edr_present" "pass" "high" "detectado: ${found[*]}"
    else
        report_event "$MODULE_ID" "edr_present" "fail" "high" "ningun EDR/agente de seguridad detectado"
    fi
}

module_apply() {
    # No destructivo: reportar estado. La instalacion del EDR es decision del operador.
    module_audit
    report_event "$MODULE_ID" "edr_policy" "skipped" "medium" "instalacion de EDR de terceros: manual/segun politica"
}
