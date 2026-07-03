#!/usr/bin/env bash
# ai/setup_ai.sh - Asistente para elegir proveedor de IA y guardar la API key.
# La clave se guarda en config/secrets.env (gitignored). Se ejecuta en TU maquina.
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS="${SCRIPT_DIR}/config/secrets.env"

if [[ -t 1 ]]; then B=$'\033[1;34m'; G=$'\033[1;32m'; C=$'\033[1;36m'; W=$'\033[1;37m'; R=$'\033[0m'
else B=""; G=""; C=""; W=""; R=""; fi

# set_secret <clave> <valor>: crea/actualiza en secrets.env
set_secret() {
    mkdir -p "$(dirname "$SECRETS")"; touch "$SECRETS"; chmod 600 "$SECRETS" 2>/dev/null
    grep -v "^$1=" "$SECRETS" > "${SECRETS}.tmp" 2>/dev/null || true
    echo "$1=\"$2\"" >> "${SECRETS}.tmp"; mv "${SECRETS}.tmp" "$SECRETS"; chmod 600 "$SECRETS" 2>/dev/null
}

printf '%b\n' "${B}================ CONFIGURAR IA ================${R}"
printf '  %b1)%b Anthropic  (Claude)        - modelo def: claude-sonnet-4-6\n' "$W" "$R"
printf '  %b2)%b OpenAI     (GPT)           - modelo def: gpt-4o-mini\n' "$W" "$R"
printf '  %b3)%b Google     (Gemini)        - modelo def: gemini-2.0-flash\n' "$W" "$R"
printf '  %b4)%b Ollama     (LOCAL, sin key)- modelo def: llama3.1\n' "$W" "$R"
printf '  %b5)%b OpenAI-compatible (endpoint propio)\n' "$W" "$R"
read -r -p "$(printf '%bElegi proveedor [1-5]: %b' "$W" "$R")" opt

local_provider=""; local_model=""; needs_key=true; needs_url=false; def_url=""
case "$opt" in
    1) local_provider="anthropic"; local_model="claude-sonnet-4-6" ;;
    2) local_provider="openai";    local_model="gpt-4o-mini" ;;
    3) local_provider="gemini";    local_model="gemini-2.0-flash" ;;
    4) local_provider="ollama";    local_model="llama3.1"; needs_key=false; needs_url=true; def_url="http://localhost:11434" ;;
    5) local_provider="openai_compatible"; local_model="gpt-4o-mini"; needs_url=true ;;
    *) echo "Opcion invalida."; exit 1 ;;
esac

read -r -p "$(printf '%bModelo [%s]: %b' "$W" "$local_model" "$R")" m_in
[[ -n "$m_in" ]] && local_model="$m_in"

api_key=""
if [[ "$needs_key" == true ]]; then
    read -r -s -p "$(printf '%bPega tu API key (no se muestra): %b' "$W" "$R")" api_key; echo
    [[ -z "$api_key" ]] && { echo "No ingresaste una key. Abortando."; exit 1; }
fi

api_url=""
if [[ "$needs_url" == true ]]; then
    read -r -p "$(printf '%bEndpoint/URL [%s]: %b' "$W" "$def_url" "$R")" api_url
    [[ -z "$api_url" ]] && api_url="$def_url"
fi

set_secret AI_PROVIDER "$local_provider"
set_secret AI_MODEL "$local_model"
set_secret AI_API_KEY "$api_key"
set_secret AI_API_URL "$api_url"

printf '%b[ OK ]%b IA configurada: %s (%s)\n' "$G" "$R" "$local_provider" "$local_model"
printf '%bClave guardada en:%b %s (gitignored)\n' "$C" "$R" "$SECRETS"
printf 'Proba el asistente con:  %b./ai/assistant.sh%b   o la opcion A del menu.\n' "$W" "$R"
