# Linux Hardening Platform

![Bash](https://img.shields.io/badge/Bash-5.x-green.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-2.0%20modular-blue.svg)

Framework **modular, no destructivo y preparado para IA** para el hardening de
endpoints Linux. Es la evolución del script base `hardening_ubuntu.sh` (conservado
en `legacy/`): en vez de un único archivo, ahora cada control es un módulo que
**emite telemetría JSON** lista para centralizar en un SIEM y para alimentar IA.

> **Principio nº1:** aditivo y no destructivo. Cada corrida SUMA controles y
> telemetría; nunca rompe ni sobrescribe el hardening ya aplicado (ledger de estado).

## 🚀 Uso rápido

```bash
git clone <tu-repo> && cd linux-hardening-platform
sudo ./install.sh

# MODO INTERACTIVO (recomendado): intro + escaneo + menu de modulos
sudo ./hardening_2.0+IA.sh
#  -> elegis un modulo por numero, o "T" para aplicar todos.
#  -> cada modulo muestra que cambiaria, pide confirmacion y da feedback.

# MODO BATCH (para cron/automatizacion):
sudo ./hardening_2.0+IA.sh --audit                  # solo lectura
sudo ./hardening_2.0+IA.sh --apply --profile server # aplica sin menu
```

## 🧩 Cómo está organizado

| Carpeta | Rol |
|---------|-----|
| `hardening_2.0+IA.sh` | Orquestador: descubre módulos, ejecuta, resume, envía telemetría |
| `lib/` | Núcleo: `core` (modos), `report` (JSON+score), `state` (ledger), `backup`, `telemetry` |
| `modules/` | Un control = un script (`10-ssh.sh`, `40-os.sh`...). Se agregan sin tocar los demás |
| `config/` | `platform.conf`, perfiles (server/workstation), on/off por módulo, supresiones |
| `integrations/` | Envío a Splunk/ELK/TheHive y alertas (Telegram/email/…) |
| `reports/` | Salida por host: `events_*.jsonl` + `resumen_*.txt/json` |
| `ai/` | Fase 2: resumen inteligente (lee reportes, no toca el sistema) |
| `legacy/` | El `hardening_ubuntu.sh` original, intacto |

## ➕ Añadir un control nuevo

Crear `modules/70-mi-control.sh` con el contrato:

```bash
MODULE_ID="mi_control"; MODULE_VERSION="1.0.0"; MODULE_SEVERITY="medium"
module_describe() { echo "Qué hace"; }
module_audit()    { report_event "$MODULE_ID" "check_x" "pass|fail" "medium" "evidencia"; }
module_apply()    { state_is_version "$MODULE_ID:x" "$MODULE_VERSION" || { backup_file X; ...; state_mark_applied "$MODULE_ID:x" "$MODULE_VERSION"; } }
```

Nada más: el orquestador lo detecta solo. Los módulos previos no se modifican.

## 📊 Reporte consolidado

Cada escaneo (`E`) o la opcion **`G » Reporte completo`** genera en `reports/<host>/`:

- `reporte_completo_<runid>.md` y `reporte_completo_<runid>.html` (abrir en navegador).

Incluye: score de postura, punto de inflexion (antes/despues), **plan de accion
(que hacer en el endpoint)**, mejoras aplicadas en la sesion, estado por modulo e
historial de mejoras (ledger). Hay un ejemplo en `docs/ejemplo_reporte.html`.

## 📡 Telemetría y alertas

- Cada evento se escribe como JSON (`reports/<host>/events_*.jsonl`) y se envía al
  destino configurado en `platform.conf` (Splunk HEC, ELK HTTP, syslog/CEF).
- Alertas por severidad y canal (Telegram/email/…), con dedupe anti-ruido.
- El módulo **no** sabe a qué SIEM va: se cambia en config, no en código.

## 🤖 Asistente IA (chat)

Elegis tu proveedor de IA y chateas con un asistente que ya conoce el estado de tu
endpoint (postura, hallazgos, plan de accion).

```bash
./ai/setup_ai.sh     # elegi proveedor (Claude/OpenAI/Gemini/Ollama/custom) + API key
./ai/assistant.sh    # abri el chat en una terminal (o usa la opcion A del menu)
```

- La API key se guarda en `config/secrets.env` (gitignored; nunca se sube).
- Proveedores soportados: Anthropic, OpenAI, Google Gemini, Ollama (local, sin key)
  y cualquier endpoint OpenAI-compatible.
- Comandos del chat: `/contexto` (recargar estado), `/reset`, `/salir`.

## 🧠 Roadmap de IA

0. Telemetría JSON ✅. 1. Resumen/recomendación IA (`ai/summarize.sh`) ✅. 2. Correlación
   con Wazuh — postura x amenazas (`ai/wazuh_correlate.sh`) ✅. 3. Reducción de FP con ML. 4. Agente MCP.
   Ver `docs/ARQUITECTURA_ESCALABLE.md`.

## 📚 Documentación

Guías detalladas (en la carpeta `docs/` y `integrations/`):

- [Arquitectura escalable del hardening](docs/ARQUITECTURA_ESCALABLE.md) — estructura, módulos, telemetría y roadmap.
- [Benchmarks (CIS) y vulnerabilidades (CVE)](docs/BENCHMARKS_Y_VULNERABILIDADES.md) — score contra estándares oficiales y punto de inflexión antes/después.
- [IA + Wazuh: SIEM inteligente](docs/IA_Y_WAZUH_SIEM.md) — cómo se conectan hardening, Suricata, auditd y Wazuh, y dónde entra la IA.
- [Despliegue multi-dispositivo](docs/DESPLIEGUE_MULTIDISPOSITIVO.md) — correr en varios endpoints, descubrimiento y publicación en GitHub.
- [Modular Cybersecurity Platform (visión)](docs/ARQUITECTURA_MCP.md) — la plataforma mayor que integra todos los módulos con IA.
- [Integración con Wazuh](integrations/wazuh/README.md) — plantillas de configuración y verificación paso a paso.

## 📄 Licencia
MIT.
