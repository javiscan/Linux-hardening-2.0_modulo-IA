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
sudo ./hardening_2.0+IA.sh --audit                 # 1) ver estado (no toca nada)
sudo ./hardening_2.0+IA.sh --dry-run               # 2) simular remediaciones
sudo ./hardening_2.0+IA.sh --apply --profile server # 3) aplicar (idempotente)
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

## 📡 Telemetría y alertas

- Cada evento se escribe como JSON (`reports/<host>/events_*.jsonl`) y se envía al
  destino configurado en `platform.conf` (Splunk HEC, ELK HTTP, syslog/CEF).
- Alertas por severidad y canal (Telegram/email/…), con dedupe anti-ruido.
- El módulo **no** sabe a qué SIEM va: se cambia en config, no en código.

## 🧠 Roadmap de IA

0. Telemetría JSON (ya). 1. Priorización determinista. 2. Resumen/recomendación con
   LLM (`ai/summarize.sh`). 3. Reducción de FP con ML. 4. Correlación (RAG).
   Ver `docs/ARQUITECTURA_ESCALABLE.md`.

## 📄 Licencia
MIT.
