#!/usr/bin/env bash
# ai/summarize.sh - (Fase 2) resume el estado de seguridad con IA.
# NO destructivo: SOLO lee el resumen JSON y produce un informe en lenguaje natural.
# Placeholder: aqui se conectaria una API LLM o un MCP server.
SUMMARY_JSON="${1:?uso: summarize.sh <resumen.json>}"
echo "[ai] (placeholder) Se enviaria ${SUMMARY_JSON} a un LLM/MCP para:"
echo "     - explicar el score en lenguaje claro"
echo "     - priorizar los criticos abiertos"
echo "     - recomendar remediaciones concretas"
# Ejemplo real (comentado):
# curl -s https://api.tu-llm/v1/chat -H "Authorization: Bearer $LLM_KEY" \
#   -d @<(jq -c '{prompt: "Resume esta postura de seguridad", data: .}' "$SUMMARY_JSON")
