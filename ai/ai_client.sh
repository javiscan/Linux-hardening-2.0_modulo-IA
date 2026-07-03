#!/usr/bin/env bash
# ai/ai_client.sh - envoltura para llamar a la IA configurada.
# ai_chat <system_prompt> <messages_json>  -> imprime la respuesta.
_AI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ai_configured() { [[ "${AI_PROVIDER:-none}" != "none" ]] && { [[ "$AI_PROVIDER" == "ollama" ]] || [[ -n "${AI_API_KEY:-}" ]]; }; }

ai_chat() {
    local system="$1" messages="${2:-[]}"
    command -v python3 >/dev/null 2>&1 || { echo "(python3 requerido para la IA)"; return 3; }
    AI_PROVIDER="${AI_PROVIDER:-none}" AI_MODEL="${AI_MODEL:-}" AI_API_KEY="${AI_API_KEY:-}" \
    AI_API_URL="${AI_API_URL:-}" AI_SYSTEM="$system" AI_MESSAGES="$messages" \
        python3 "${_AI_DIR}/_ai_call.py"
}
