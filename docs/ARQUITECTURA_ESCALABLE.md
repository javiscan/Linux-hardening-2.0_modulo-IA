# Arquitectura Escalable del Hardening Linux

> Cómo evolucionar `hardening_ubuntu.sh` (script monolítico actual) hacia un
> **framework de hardening modular, no destructivo, con telemetría unificada,
> alertas multicanal y preparado para IA** — manteniendo Bash como base.
>
> **Principio rector nº1:** el hardening base ya aplicado NO se rompe ni se
> sobrescribe. Cada versión SUMA controles y telemetría de forma aditiva.

---

## 1. Diagnóstico del código actual

`hardening_ubuntu.sh` (~890 líneas, single-file) ya tiene bases excelentes que
vamos a **conservar y estandarizar**, no a tirar:

- Helpers de I/O y logging, paleta de colores, `confirm`.
- Motor de modos `--audit` / `--dry-run` (clave para no ser destructivo).
- `backup_file` con timestamp e idempotencia (`set_config_kv`, drop-ins).
- Módulos como funciones (SSH, logging, parches, OS, red, DNS).

**Limitación para escalar:** todo vive en un archivo; los módulos no producen una
**salida estructurada** (JSON) que se pueda centralizar, correlacionar o alimentar
a una IA. Ese es el cambio de fondo: pasar de "imprime texto" a "**emite eventos
estructurados**" y separar el monolito en un framework de piezas pequeñas.

---

## 2. Estructura recomendada del proyecto

```
linux-hardening-platform/
├── harden.sh                     # ORQUESTADOR (unico entrypoint)
├── install.sh                    # git clone + ./install.sh (despliegue)
├── VERSION                       # version del framework (semver)
├── config/
│   ├── platform.conf             # nivel de hardening, SIEM endpoints, canales
│   ├── modules.d/                # on/off y parametros por modulo
│   │   ├── 10-ssh.conf
│   │   └── ...
│   ├── profiles/                 # server.profile / workstation.profile
│   └── suppressions.yml          # excepciones (gestion de falsos positivos)
├── lib/                          # librerias compartidas (se sourcean)
│   ├── core.sh                   # logging, colores, run(), modos
│   ├── backup.sh                 # backups con timestamp
│   ├── state.sh                  # LEDGER: que se aplico, version, checksum
│   ├── report.sh                 # emision de eventos JSON + score
│   └── telemetry.sh              # envio a SIEM + dispatcher de alertas
├── modules/                      # UN control = UN script independiente
│   ├── 00-prereqs.sh
│   ├── 10-ssh.sh
│   ├── 20-logging.sh
│   ├── 30-patches.sh
│   ├── 40-os.sh
│   ├── 50-network.sh
│   ├── 60-dns.sh
│   └── 70-<nuevo-control>.sh     # se AGREGA sin tocar los anteriores
├── integrations/
│   ├── splunk/                   # config HEC / forwarder
│   ├── elk/                      # filebeat/fluent-bit + pipelines
│   ├── thehive/                  # creacion de casos via API
│   └── alerts/                   # email / telegram / whatsapp / sms
├── reports/                      # salida por host: eventos.jsonl + resumen
├── ai/                           # placeholders + roadmap (fase futura)
├── tests/                        # bats (helpers puros, sin root)
└── docs/
```

**Migración sin dolor:** el `hardening_ubuntu.sh` actual se conserva tal cual como
"modo legacy / single-host", y sus 6 puntos se van extrayendo uno a uno a
`modules/`. No hay big-bang: coexisten.

---

## 3. Cómo organizar los scripts Bash (contrato de módulo)

Cada archivo en `modules/` es autónomo y cumple un **contrato** de 3 funciones.
El orquestador los descubre por nombre (orden numérico) y los ejecuta según config.

```bash
# modules/10-ssh.sh
# Cada modulo declara metadatos y expone: describe / audit / apply
MODULE_ID="ssh"
MODULE_VERSION="1.2.0"
MODULE_SEVERITY="high"
MODULE_CIS="5.2"

module_describe() {
  echo "Hardening de SSH: root off, puerto, auth por clave, MaxAuthTries."
}

# audit(): NO cambia nada. Devuelve estado -> report_event
module_audit() {
  local root_login
  root_login="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/ {print $2}')"
  if [[ "$root_login" == "no" ]]; then
    report_event "$MODULE_ID" "ssh_root_login" "pass" "$MODULE_SEVERITY" "root deshabilitado"
  else
    report_event "$MODULE_ID" "ssh_root_login" "fail" "$MODULE_SEVERITY" "PermitRootLogin=$root_login"
  fi
}

# apply(): remedia SOLO lo que falta. Idempotente. Respeta backups y state.
module_apply() {
  state_is_applied "${MODULE_ID}:ssh_root_login" && return 0   # no re-aplica
  backup_file /etc/ssh/sshd_config
  set_config_kv /etc/ssh/sshd_config PermitRootLogin no
  sshd -t && systemctl reload ssh
  state_mark_applied "${MODULE_ID}:ssh_root_login" "$MODULE_VERSION"
  report_event "$MODULE_ID" "ssh_root_login" "applied" "$MODULE_SEVERITY" "remediado"
}
```

Ventajas:
- **Aditivo por diseño**: agregar un control = crear `70-....sh`. Los módulos
  existentes ni se tocan.
- **Auditable**: `module_audit` corre en modo solo lectura y produce el estado.
- **No destructivo**: `apply` consulta el **ledger de estado** antes de actuar y
  nunca elimina configuración previa; solo añade lo que falta.

---

## 4. Modularidad, escalabilidad y NO destrucción

### 4.1 Ledger de estado (`lib/state.sh`)
Archivo `/var/lib/hardening/state.json`: registra cada control aplicado, su
versión y un checksum. Esto garantiza:
- **Idempotencia total**: re-ejecutar no re-aplica ni pisa nada.
- **Mejora continua**: si sube la versión de un control, el runner detecta el
  delta y aplica SOLO lo nuevo, sin rehacer lo ya endurecido.
- **Trazabilidad**: sabés qué versión de hardening tiene cada endpoint.

### 4.2 Baseline y excepciones (gestión de FP)
- La primera auditoría genera un **baseline** del host.
- `config/suppressions.yml` define estados "conocidos-buenos" que no deben
  alertar (p. ej. un puerto abierto legítimo). Así separás **falsos positivos**
  de hallazgos reales.

### 4.3 Perfiles y niveles
- `profiles/server.profile` vs `workstation.profile`: distinto set de módulos.
- `platform.conf` define nivel (básico/estricto) → mismo código, distinta postura.

### 4.4 Orquestador (`harden.sh`)
Descubre módulos, respeta config/perfil, corre en `--audit`/`--dry-run`/`--apply`,
agrega resultados y dispara telemetría + resumen. Un solo punto de entrada.

---

## 5. Telemetría unificada (el corazón de la escalabilidad)

**Regla:** todo módulo emite un **evento JSON** con esquema estable. Ese JSON es
lo que hace posible centralizar, correlacionar, alertar y —más adelante— usar IA.

Esquema de evento (`lib/report.sh` → `report_event`):

```json
{
  "timestamp": "2026-07-02T10:15:03Z",
  "host": "web-01",
  "os": "Ubuntu 24.04",
  "framework_version": "2.0.0",
  "module": "ssh",
  "control_id": "ssh_root_login",
  "cis": "5.2",
  "status": "fail",            // pass | fail | applied | skipped
  "severity": "high",
  "evidence": "PermitRootLogin=yes",
  "run_id": "a1b2c3"
}
```

Se escribe en `reports/<host>/events.jsonl` (una línea por evento) y se **envía**
por `lib/telemetry.sh`, que abstrae el destino:

| Destino    | Mecanismo recomendado                                             |
|------------|------------------------------------------------------------------|
| **ELK**    | Filebeat/Fluent Bit leyendo `reports/*.jsonl` → pipeline ingest   |
| **Splunk** | HTTP Event Collector (HEC) vía `curl` con token                   |
| **TheHive**| API REST: crea un caso/alerta cuando `status=fail severity>=high` |
| **Syslog** | rsyslog en formato **CEF** para cualquier SIEM genérico           |

Ejemplo de envío a Splunk HEC (dentro de `telemetry.sh`):

```bash
telemetry_splunk() {
  local event="$1"
  curl -sk -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN}" \
       "https://${SPLUNK_HOST}:8088/services/collector/event" \
       -d "{\"event\": ${event}, \"sourcetype\": \"hardening:event\"}" >/dev/null
}
```

Diseño clave: **el módulo no sabe a qué SIEM va**. Cambiar de ELK a Splunk = editar
`platform.conf`, no los módulos. Escala a N endpoints sin reescribir nada.

---

## 6. Alertas inteligentes multicanal

`integrations/alerts/` contiene un **dispatcher** que, ante hallazgos por encima de
un umbral de severidad (y que no estén suprimidos), notifica por los canales
configurados. Cada canal es un script pequeño e intercambiable.

```bash
# integrations/alerts/dispatch.sh
alert_dispatch() {
  local sev="$1" title="$2" body="$3"
  severity_ge "$sev" "$ALERT_MIN_SEVERITY" || return 0     # umbral
  is_suppressed "$title" && return 0                        # anti falso-positivo
  dedupe "$title" || return 0                               # anti-spam (rate limit)
  for ch in ${ALERT_CHANNELS}; do
    case "$ch" in
      email)    alert_email    "$title" "$body" ;;
      telegram) alert_telegram "$title" "$body" ;;
      whatsapp) alert_whatsapp "$title" "$body" ;;
      sms)      alert_sms      "$title" "$body" ;;
    esac
  done
}
```

Notas por canal:
- **Email**: `msmtp`/`sendmail` (simple) o API (SendGrid/SES) para escala.
- **Telegram**: Bot API (`curl` a `sendMessage`) — el más rápido de montar.
- **WhatsApp**: WhatsApp Cloud API o Twilio.
- **SMS**: Twilio / proveedor local.
- **Anti-ruido**: dedupe + rate-limit + suppressions = menos fatiga de alertas
  (esto es lo que distingue un sistema usable de uno que todos silencian).

---

## 7. Detección y respuesta (TP / FP / FN)

- **Positivos (TP)**: `status=fail` real → evento + alerta + (opcional) caso en
  TheHive. Enriquecible con TI en fase IA.
- **Falsos positivos (FP)**: se gestionan con `suppressions.yml` + baseline. Un FP
  confirmado se agrega a supresiones y deja de alertar.
- **Falsos negativos (FN)**: se combaten con **mejora continua** (cada versión
  suma controles) y con la comparación baseline↔estado actual (detecta desvíos).
- **Feedback loop**: el equipo marca alertas como TP/FP; ese etiquetado es el
  dataset que luego entrena la reducción de FP con ML (fase IA).

---

## 8. Resumen de estado por dispositivo

Al final de cada corrida, `lib/report.sh` genera:
- **Score de postura** (0–100), ponderado por severidad y mapeado a CIS.
- **Resumen legible** (`reports/<host>/resumen.txt`) y **JSON** para máquinas.
- Opcional: **HTML** para adjuntar a un ticket o publicar.

```
==== RESUMEN DE SEGURIDAD — web-01 (Ubuntu 24.04) ====
Score de postura: 82/100  (CIS parcial)
Controles: 41 pass · 7 fail · 3 suppressed
Críticos abiertos: 2  -> [ssh_password_auth, ufw_disabled]
Framework: v2.0.0 | run_id a1b2c3 | 2026-07-02 10:15
Enviado a: Splunk HEC, Telegram
```

Este resumen es, además, la entrada natural para que una IA lo explique en
lenguaje claro y recomiende los próximos pasos (fase 2 del roadmap).

---

## 9. Despliegue (git clone + ejecución)

```bash
git clone https://github.com/TU_USUARIO/linux-hardening-platform
cd linux-hardening-platform
sudo ./install.sh          # valida deps, crea /var/lib/hardening, permisos
sudo ./harden.sh --audit   # 1) ver estado sin tocar nada
sudo ./harden.sh --dry-run # 2) simular
sudo ./harden.sh --apply --profile server   # 3) aplicar de forma idempotente
```

`install.sh` deja todo listo (ledger, config de ejemplo, cron opcional para
auditorías periódicas que envían telemetría al SIEM sin intervención humana).

---

## 10. Roadmap para añadir IA progresivamente

La IA se suma SIN reescribir el hardening. La clave es que ya emitimos JSON.

**Fase 0 — Cimiento de datos (ya en esta arquitectura)**
- Telemetría JSON estandarizada + score. *Sin datos estructurados no hay IA útil.*

**Fase 1 — Inteligencia determinista (semanas)**
- Priorización por reglas (severidad × exposición × criticidad del host).
- Supresión/baseline para FP. Es "pre-IA" pero resuelve el 60% del valor.

**Fase 2 — IA de resumen y recomendación (1 script, API)**
- `ai/summarize.sh`: envía el resumen JSON a una API LLM (o a un MCP server) y
  devuelve un informe en lenguaje natural + remediaciones priorizadas.
- No toca el hardening; solo lee reportes. Riesgo mínimo, valor alto.

**Fase 3 — Triage y reducción de FP con ML**
- Modelo entrenado con el etiquetado TP/FP del equipo (sección 7).
- Filtra ruido antes de alertar. Menos fatiga, mejores decisiones.

**Fase 4 — Correlación y contexto (RAG)**
- Indexar eventos + knowledge (CIS, MITRE ATT&CK) en un vector store.
- Relacionar hallazgos entre endpoints; "este patrón ya se vio en otro host".

**Fase 5 — Agente de recomendación de controles**
- Un agente que, viendo la postura, **propone nuevos módulos de hardening**
  (código Bash) para revisión humana. La mejora continua, asistida por IA.
- Se conecta con la "Modular Cybersecurity Platform" (doc aparte): este hardening
  es la **fuente de postura** que alimenta el triage de incidentes.

---

## 11. Prioridades (qué hacer primero)

1. **Extraer `lib/core.sh`, `report.sh`, `state.sh`** del script actual y hacer que
   cada punto emita eventos JSON. (Máximo impacto: habilita todo lo demás.)
2. **Mover los 6 puntos a `modules/`** con el contrato audit/apply, sin cambiar su
   lógica interna (que ya funciona). Coexiste con el script legacy.
3. **`telemetry.sh` + un destino** (Telegram para alertas, Splunk/ELK para logs).
4. **Score + resumen por host.**
5. Recién entonces, **Fase 2 de IA** (resumen con LLM). 

> Regla de oro: estabilidad del hardening primero. La IA se enchufa al final del
> pipeline (lee reportes), nunca en el camino crítico que modifica el sistema.
