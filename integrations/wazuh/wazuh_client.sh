#!/usr/bin/env bash
# integrations/wazuh/wazuh_client.sh
# Cliente minimo y de SOLO LECTURA para Wazuh. Dos superficies:
#   - Manager API (55000): SCA, agentes, vulnerabilidades (segun version).
#   - Indexer/OpenSearch (9200): alertas indexadas (Suricata, auth, etc.).
# Config (en config/secrets.env, NO subir a git):
#   WAZUH_API_URL=https://MANAGER:55000  WAZUH_API_USER=..  WAZUH_API_PASS=..
#   WAZUH_INDEXER_URL=https://INDEXER:9200  WAZUH_INDEXER_USER=..  WAZUH_INDEXER_PASS=..
: "${WAZUH_API_URL:=}"; : "${WAZUH_API_USER:=}"; : "${WAZUH_API_PASS:=}"
: "${WAZUH_INDEXER_URL:=}"; : "${WAZUH_INDEXER_USER:=}"; : "${WAZUH_INDEXER_PASS:=}"
WAZUH_TOKEN=""

wazuh_api_available()     { [[ -n "$WAZUH_API_URL" && -n "$WAZUH_API_USER" && -n "$WAZUH_API_PASS" ]] && command -v curl >/dev/null 2>&1; }
wazuh_indexer_available() { [[ -n "$WAZUH_INDEXER_URL" && -n "$WAZUH_INDEXER_USER" && -n "$WAZUH_INDEXER_PASS" ]] && command -v curl >/dev/null 2>&1; }

wazuh_auth() {
    wazuh_api_available || return 1
    WAZUH_TOKEN="$(curl -sk -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -X POST \
        "${WAZUH_API_URL}/security/user/authenticate?raw=true" 2>/dev/null)"
    [[ -n "$WAZUH_TOKEN" ]]
}

wazuh_api_get() {   # wazuh_api_get <path>
    [[ -n "$WAZUH_TOKEN" ]] || wazuh_auth || return 1
    curl -sk --max-time 15 -H "Authorization: Bearer ${WAZUH_TOKEN}" "${WAZUH_API_URL}$1" 2>/dev/null
}

# Cuenta documentos en el indexer para una query lucene (ej: rule.groups:ids)
wazuh_indexer_count() {   # wazuh_indexer_count <lucene_query>
    wazuh_indexer_available || return 1
    curl -sk --max-time 15 -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" \
        "${WAZUH_INDEXER_URL}/wazuh-alerts-*/_count" \
        -H 'Content-Type: application/json' \
        -d "{\"query\":{\"query_string\":{\"query\":\"$1\"}}}" 2>/dev/null \
        | grep -oE '"count":[0-9]+' | head -n1 | cut -d: -f2
}
