#!/usr/bin/env python3
# Motor de llamada a distintos proveedores de IA. Lee de variables de entorno:
#   AI_PROVIDER, AI_MODEL, AI_API_KEY, AI_API_URL, AI_SYSTEM, AI_MESSAGES(json)
# Imprime la respuesta del asistente en stdout. Sale != 0 ante error.
import sys, os, json, urllib.request

prov  = os.environ.get("AI_PROVIDER", "none")
model = os.environ.get("AI_MODEL", "")
key   = os.environ.get("AI_API_KEY", "")
url   = os.environ.get("AI_API_URL", "")
system= os.environ.get("AI_SYSTEM", "")
try:
    msgs = json.loads(os.environ.get("AI_MESSAGES", "[]"))
except Exception:
    msgs = []
TIMEOUT = 90

def post(u, body, headers):
    req = urllib.request.Request(u, data=json.dumps(body).encode(), headers=headers)
    return json.load(urllib.request.urlopen(req, timeout=TIMEOUT))

try:
    if prov == "anthropic":
        u = url or "https://api.anthropic.com/v1/messages"
        body = {"model": model or "claude-sonnet-4-6", "max_tokens": 1500,
                "system": system, "messages": msgs}
        h = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        r = post(u, body, h); sys.stdout.write(r["content"][0]["text"])
    elif prov in ("openai", "openai_compatible"):
        base = url or "https://api.openai.com/v1"
        m = ([{"role": "system", "content": system}] + msgs) if system else msgs
        body = {"model": model or "gpt-4o-mini", "messages": m}
        h = {"Authorization": "Bearer " + key, "content-type": "application/json"}
        r = post(base + "/chat/completions", body, h)
        sys.stdout.write(r["choices"][0]["message"]["content"])
    elif prov == "gemini":
        mdl = model or "gemini-2.0-flash"
        u = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s" % (mdl, key)
        contents = []
        if system:
            contents.append({"role": "user", "parts": [{"text": "[Contexto del sistema]\n" + system}]})
        for m in msgs:
            role = "model" if m.get("role") == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": m.get("content", "")}]})
        r = post(u, {"contents": contents}, {"content-type": "application/json"})
        sys.stdout.write(r["candidates"][0]["content"]["parts"][0]["text"])
    elif prov == "ollama":
        base = url or "http://localhost:11434"
        m = ([{"role": "system", "content": system}] + msgs) if system else msgs
        body = {"model": model or "llama3.1", "messages": m, "stream": False}
        r = post(base + "/api/chat", body, {"content-type": "application/json"})
        sys.stdout.write(r["message"]["content"])
    else:
        sys.stderr.write("Proveedor IA no configurado. Corre: ./ai/setup_ai.sh\n"); sys.exit(2)
except Exception as e:
    sys.stderr.write("AI error: %s\n" % e); sys.exit(3)
