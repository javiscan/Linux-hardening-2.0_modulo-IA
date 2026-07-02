# Modular Cybersecurity Platform (MCP) — Arquitectura y Roadmap

> Documento de diseño técnico. Objetivo: evolucionar el toolkit de hardening
> actual hacia una plataforma **modular, automatizada e inteligente** que integre
> Threat Intel, escaneo, pentesting, detección (SIEM), respuesta (SOAR) y DFIR,
> con IA en el núcleo. Escrito para ser accionable y priorizado por impacto.

---

## 0. Aclaración clave de nomenclatura: dos "MCP"

Hay dos conceptos que comparten sigla y conviene no confundir:

- **MCP (tu plataforma)** = *Modular Cybersecurity Platform*.
- **MCP (protocolo)** = *Model Context Protocol* (Anthropic). Es el estándar que
  usan proyectos como "Nmap MCP Server" o "Jordan MCP": **exponen una herramienta
  de seguridad como un servidor que un agente de IA (LLM) puede invocar** de forma
  estructurada, con esquema de entradas/salidas.

**Decisión de diseño central**: usar *Model Context Protocol* como **columna
vertebral de integración con IA**. Cada herramienta (Nmap, VirusTotal, Shodan,
Wazuh, Volatility...) se envuelve en un **MCP Server**; un **agente orquestador**
razona y decide qué servidores llamar. Esto te da modularidad + IA "gratis":
agregar una herramienta = agregar un MCP server, sin tocar el cerebro del sistema.

---

## 1. Principios de diseño

1. **Modularidad plug-in**: cada capacidad es un módulo desacoplado con contrato
   claro (API/MCP). Se puede activar/desactivar sin romper el resto.
2. **Event-driven**: los módulos se comunican por un bus de eventos, no por
   llamadas directas. Facilita escalar y auditar.
3. **Schema-first (normalización)**: todo evento se normaliza a un esquema común
   (**OCSF** u **ECS**) antes de procesarse. Sin esto, la correlación e IA fallan.
4. **Human-in-the-loop en acciones destructivas**: la IA propone; un humano (o una
   policy explícita) aprueba respuestas con impacto (aislar host, bloquear IP).
5. **Least privilege + auditabilidad**: cada módulo y cada agente con permisos
   mínimos; todo lo que hace la IA queda logueado.
6. **Todo containerizado y reproducible**: Docker Compose (dev) → Kubernetes (prod).

---

## 2. Arquitectura de referencia (capas)

```
                        +--------------------------------------+
                        |        Presentación / API            |
                        |  Dashboard web + FastAPI + Chat NL   |
                        +------------------+-------------------+
                                           |
        +----------------------------------+----------------------------------+
        |                       Capa de IA / Orquestación                     |
        |  Agentes (LangGraph / Claude Agent SDK) · RAG · triage · playbooks  |
        +----------------------------------+----------------------------------+
                                           |  (Model Context Protocol)
   +-----------+-----------+-----------+---+-------+-----------+--------------+
   |  Threat   |  Scanning |  Pentest  | Detection| Response  |     DFIR     |
   |  Intel    |  (Nmap,   |  (Kali    | (Wazuh,  | (SOAR,    | (Volatility, |
   | (VT,Shodan|  Nessus,  |  tools)   | Suricata)| Defender) |  Autopsy)    |
   |  MISP)    |  OpenVAS) |           |          |           |              |
   +-----------+-----------+-----------+----------+-----------+--------------+
        |            (cada herramienta = un MCP Server / adaptador)          |
        +----------------------------------+----------------------------------+
                                           |
        +----------------------------------+----------------------------------+
        |     Núcleo: Bus de eventos · Normalización OCSF · Almacenamiento    |
        |   Redis/NATS/Kafka · Postgres · OpenSearch · Vector DB (pgvector)   |
        +---------------------------------------------------------------------+
```

**Flujo típico**: un colector genera un evento → se normaliza a OCSF → entra al bus
→ el módulo de detección correlaciona → si hay hallazgo, la capa de IA lo enriquece
(TI), lo prioriza y arma un caso → SOAR ejecuta un playbook (con aprobación si es
destructivo) → todo queda indexado y consultable en lenguaje natural.

---

## 3. Estructura del proyecto

```
modular-cybersecurity-platform/
├── docker-compose.yml            # stack de desarrollo (tier Lite/Pro)
├── .env.example                  # secretos y config (NUNCA commitear .env real)
├── pyproject.toml                # gestion de deps (uv/poetry)
├── core/
│   ├── bus/                      # abstraccion del bus de eventos (Redis/NATS)
│   ├── schema/                   # modelos OCSF/ECS (pydantic)
│   ├── storage/                  # repos: Postgres, OpenSearch, vector
│   └── config/                   # carga de config y policies
├── modules/                      # un subpaquete por capacidad
│   ├── threat_intel/             # VirusTotal, Shodan, MISP
│   ├── scanning/                 # Nmap, Nessus, OpenVAS
│   ├── pentest/                  # wrappers Kali (autorizado)
│   ├── detection/                # Wazuh, Suricata, reglas Sigma
│   ├── response/                 # SOAR playbooks, Defender XDR
│   ├── dfir/                     # Volatility, Autopsy (dockerizado)
│   └── hardening/                # <-- tu script actual, ver seccion 12
├── mcp_servers/                  # servidores Model Context Protocol por tool
│   ├── nmap_server.py
│   ├── virustotal_server.py
│   ├── wazuh_server.py
│   └── ...
├── ai/
│   ├── agents/                   # triage, correlacion, IR (LangGraph)
│   ├── rag/                      # ingest + retrieval sobre eventos/knowledge
│   ├── prompts/                  # plantillas versionadas
│   └── guardrails/               # validacion I/O, anti prompt-injection
├── api/                          # FastAPI (REST + WebSocket para chat)
├── playbooks/                    # definiciones SOAR (YAML)
├── deploy/
│   ├── compose/                  # overrides por entorno
│   └── k8s/                      # manifests/Helm (tier Enterprise)
├── tests/
└── docs/
```

Regla: **un módulo no importa a otro directamente**. Se comunican por el bus y
comparten solo el `core/schema`. Así podés reemplazar Wazuh por otro SIEM tocando
un único módulo.

---

## 4. Los seis módulos (tecnología + cómo se integran)

### 4.1 Threat Intelligence & Reconnaissance
- **Herramientas**: VirusTotal, Shodan, AbuseIPDB, GreyNoise, **MISP** (para
  correlación y feeds), theHarvester/Amass (OSINT pasivo).
- **Integración**: cada API → un MCP Server con funciones como
  `vt_lookup(hash|ip|domain)`, `shodan_host(ip)`. El agente los llama para
  **enriquecer** cualquier indicador (IOC) que aparezca en una alerta.
- **Automatización IA**: cuando entra un IOC nuevo, se enriquece solo, se calcula
  un score de reputación y se decide si abrir caso.

### 4.2 Escaneo de Redes y Vulnerabilidades
- **Herramientas**: Nmap (descubrimiento/servicios), **Nessus** u **OpenVAS**
  (vuln scanning), opcional `nuclei` (rápido, plantillas).
- **Integración**: `nmap_server` (MCP) + parser a OCSF; scanner de vulns como
  módulo que dispara escaneos programados y normaliza CVEs.
- **Automatización IA**: correlación CVE ↔ inventario del host (el que ya genera
  tu script de hardening) para **priorizar por explotabilidad + exposición**
  (EPSS + CVSS + si el puerto está expuesto), no solo por CVSS.

### 4.3 Pentesting y Red Team
- **Herramientas**: subset de Kali (nmap, nikto, sqlmap, hydra, Metasploit RPC).
- **Integración**: wrappers con **guardrails duros**: solo contra targets en una
  allowlist firmada, con confirmación humana y "rules of engagement" en config.
- **Automatización IA**: un agente que sugiere el siguiente paso lógico de un
  pentest autorizado (recon → enum → validación), documentando cada acción.
  *Nunca* ejecución destructiva sin aprobación explícita.

### 4.4 Detección y Monitoreo (SIEM)
- **Herramientas**: **Wazuh** (HIDS + gestor de alertas), **Suricata** (NIDS),
  reglas **Sigma** (portables entre backends).
- **Integración**: Wazuh como fuente principal de alertas → normalización OCSF →
  bus. Tu script de hardening ya deja auditd/Suricata listos para alimentarlo.
- **Automatización IA**: reducción de falsos positivos (clasificador ML + LLM que
  explica la alerta), agrupación de alertas relacionadas en un solo caso.

### 4.5 Incident Response & Orchestration (SOAR)
- **Herramientas**: **Shuffle** o **n8n** (motor de playbooks open-source),
  integración con **Microsoft Defender XDR** (API Graph Security), TheHive/Cortex.
- **Integración**: playbooks en YAML versionados; acciones idempotentes y
  reversibles; aprobación humana para lo destructivo.
- **Automatización IA (reduce MTTR)**: el agente arma el caso, propone el playbook,
  redacta la comunicación y, tras aprobación, orquesta la contención. Métrica
  objetivo: MTTR ↓ por triage y enriquecimiento automáticos.

### 4.6 Digital Forensics & IR (DFIR)
- **Herramientas**: **Volatility 3** (memoria), **Autopsy**/Sleuth Kit (disco),
  YARA, Plaso/timesketch (timeline).
- **Integración**: entorno **dockerizado** aislado; se lanza bajo demanda cuando
  un caso escala a forense. Resultados normalizados y adjuntos al caso.
- **Automatización IA**: resumen automático de artefactos, generación de timeline
  narrado y sugerencia de hipótesis de la cadena de ataque (mapeo MITRE ATT&CK).

---

## 5. Integración de IA — casos concretos y cómo implementarlos

Priorizados por impacto/esfuerzo (primero lo más rentable):

1. **Triage y priorización de alertas** *(alto impacto, bajo esfuerzo)*
   - LLM recibe la alerta normalizada + enriquecimiento TI y devuelve:
     severidad, probabilidad de FP, y "por qué". Se combina con score
     determinista (CVSS/EPSS/exposición) para no depender solo del LLM.
2. **Resumen y narrativa de incidentes** *(alto/bajo)*
   - Convierte N alertas técnicas en un caso legible + próximos pasos.
3. **Correlación multi-fuente vía RAG** *(alto/medio)*
   - Indexás eventos/knowledge (MITRE, runbooks) en un **vector store**; el agente
     recupera contexto para relacionar eventos que un motor de reglas no une.
4. **Recomendación y auto-generación de playbooks** *(alto/medio)*
   - El agente propone el playbook SOAR (YAML) para el tipo de incidente.
5. **Consulta en lenguaje natural** *(medio/bajo)*
   - "¿Qué hosts con CVE crítica tienen el puerto expuesto?" → el agente traduce a
     queries sobre OpenSearch/Postgres.
6. **Reducción de falsos positivos con ML** *(medio/medio)*
   - Clasificador (histórico etiquetado) que filtra ruido antes del LLM (ahorra coste).

**Patrón de implementación recomendado**: agentes con **LangGraph** (control de
flujo, estados, reintentos) o el **Claude Agent SDK**, consumiendo herramientas
por **Model Context Protocol**. RAG con **pgvector** o **Qdrant**.

---

## 6. Enfoques por nivel (Lite → Pro → Enterprise)

| Aspecto            | Lite (fin de semana)        | Pro (equipo pequeño)             | Enterprise                         |
|--------------------|-----------------------------|----------------------------------|------------------------------------|
| Despliegue         | Docker Compose, 1 host      | Compose/Swarm, varios servicios  | Kubernetes + Helm, HA              |
| Bus de eventos     | Redis Streams               | NATS / Redis                     | Kafka                              |
| Almacenamiento     | SQLite/Postgres + JSON      | Postgres + OpenSearch            | Data lake + OpenSearch + Postgres  |
| Normalización      | ECS ligero                  | OCSF                             | OCSF completo + data quality       |
| Módulos activos    | TI + Nmap + Wazuh + triage  | + Vulns + SOAR + RAG             | Los 6 + DFIR + multi-tenant        |
| IA                 | 1 agente triage             | Agentes multiples + RAG          | Agentes + guardrails + eval/telem  |
| SOAR               | scripts Python              | Shuffle/n8n                      | Shuffle + Defender XDR + TheHive   |
| Auth/RBAC          | básica                      | OIDC                             | OIDC + RBAC fino + audit + Vault   |

**Recomendación**: arrancá en **Lite** con un vertical completo (TI → detección →
triage IA) funcionando de punta a punta. Un módulo end-to-end vale más que seis a
medias. Después escalás a Pro.

---

## 7. Stack tecnológico recomendado

- **Lenguaje/core**: Python 3.12, **FastAPI**, **Pydantic v2** (schemas).
- **IA**: **Model Context Protocol** (SDK oficial), **LangGraph** o **Claude Agent
  SDK**, LangChain para utilidades, **pgvector/Qdrant** (RAG).
- **Mensajería**: Redis Streams (Lite) → NATS → Kafka (Enterprise).
- **Datos**: Postgres (casos/estado), OpenSearch/Elastic (búsqueda de eventos).
- **Contenedores**: Docker + Compose → **Kubernetes** + Helm.
- **Seguridad de secretos**: `.env` + **HashiCorp Vault** (Pro/Enterprise).
- **SOAR**: **Shuffle** (open-source, MITRE-friendly) o **n8n**.
- **Normalización**: **OCSF** (estándar abierto respaldado por la industria).
- **Infra-as-code / hardening**: reutilizá **Ansible** para portar tu script.
- **Observabilidad**: OpenTelemetry + Grafana (y para IA: trazas de agentes).

---

## 8. Ejemplos de código

### 8.1 MCP Server que envuelve Nmap (Python, SDK oficial)

```python
# mcp_servers/nmap_server.py
import asyncio, json, shlex, subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nmap-server")

ALLOWED_FLAGS = {"-sV", "-sC", "-Pn", "-p", "-T4", "-O", "--top-ports"}

def _sanitize(args: str) -> list[str]:
    parts = shlex.split(args)
    for p in parts:
        if p.startswith("-") and p.split("=")[0] not in ALLOWED_FLAGS:
            raise ValueError(f"Flag no permitido: {p}")
    return parts

@mcp.tool()
def nmap_scan(target: str, options: str = "-sV -T4") -> dict:
    """Escanea un target autorizado y devuelve servicios/puertos normalizados."""
    # Guardrail: el target debe estar en la allowlist (rules of engagement)
    if not _authorized(target):
        return {"error": "target no autorizado"}
    cmd = ["nmap", "-oX", "-", *_sanitize(options), target]
    xml = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
    return {"target": target, "raw_xml": xml, "ocsf": _to_ocsf(xml)}

def _authorized(target: str) -> bool:
    with open("config/scope_allowlist.json") as f:
        return target in json.load(f)["targets"]

if __name__ == "__main__":
    mcp.run()
```

Patrón replicable: mismo esqueleto para `virustotal_server.py`, `shodan_server.py`,
`wazuh_server.py`. Cada uno expone `@mcp.tool()` con validación de entrada.

### 8.2 Agente de triage (LangGraph, pseudo-flujo)

```python
# ai/agents/triage.py  (esquema conceptual)
from langgraph.graph import StateGraph, END

def enrich(state):        # llama MCP TI (VirusTotal/Shodan)
    state["ti"] = ti_lookup(state["alert"]["iocs"]); return state

def score(state):         # score determinista (CVSS/EPSS/exposicion)
    state["risk"] = risk_engine(state["alert"], state["ti"]); return state

def llm_triage(state):    # LLM: severidad + prob. FP + explicacion
    state["verdict"] = llm.classify(state["alert"], state["ti"], state["risk"])
    return state

def route(state):         # decide: cerrar, caso, o escalar a humano
    return "case" if state["verdict"]["severity"] >= 3 else "close"

g = StateGraph(dict)
g.add_node("enrich", enrich); g.add_node("score", score)
g.add_node("triage", llm_triage)
g.add_edge("enrich", "score"); g.add_edge("score", "triage")
g.add_conditional_edges("triage", route, {"case": "open_case", "close": END})
```

### 8.3 docker-compose (tier Lite, extracto)

```yaml
services:
  api:        { build: ./api, env_file: .env, ports: ["8000:8000"] }
  redis:      { image: redis:7 }
  postgres:   { image: postgres:16, env_file: .env }
  opensearch: { image: opensearchproject/opensearch:2 }
  wazuh:      { image: wazuh/wazuh-manager:4.9 }
  mcp-nmap:   { build: ./mcp_servers, command: python nmap_server.py }
  agent:      { build: ./ai, env_file: .env, depends_on: [redis, postgres] }
```

---

## 9. Seguridad de la propia plataforma (crítico)

Una plataforma que ingiere datos hostiles y los pasa a un LLM tiene riesgos
propios. No omitas esto:

1. **Prompt injection vía datos de herramientas**: la salida de Nmap, un correo o
   un log pueden contener texto que intente manipular al agente. Trata TODA salida
   de herramienta como **datos, no instrucciones**. Usa plantillas que delimiten
   claramente el contenido no confiable y valida las acciones propuestas.
2. **Human-in-the-loop** obligatorio para acciones destructivas (aislar, borrar,
   bloquear, ejecutar exploits).
3. **Least privilege**: cada MCP server con credenciales mínimas y de solo lectura
   cuando sea posible; secretos en Vault, nunca en el prompt.
4. **Allowlist de alcance** para scanning/pentest (rules of engagement firmadas).
5. **Auditoría total de la IA**: loguear prompt, herramientas llamadas y decisión.
6. **Evaluación y telemetría** de los agentes (tasa de FP, alucinaciones) antes de
   darles más autonomía.

---

## 10. Roadmap por fases (priorizado por impacto)

**Fase 0 — Fundaciones (semana 1–2)**
- Estructura de repo, `core/schema` (OCSF mínimo), bus Redis, Compose base.
- Portar el script de hardening como módulo (sección 11).

**Fase 1 — Primer vertical end-to-end (semana 3–4)** *(máximo impacto)*
- Wazuh como fuente → normalización → **agente de triage IA** → caso en Postgres.
- MCP server de VirusTotal para enriquecer. Dashboard mínimo.

**Fase 2 — Visibilidad y escaneo (mes 2)**
- MCP server de Nmap + módulo de vulnerabilidades (OpenVAS/Nessus).
- Priorización IA CVE ↔ exposición ↔ inventario.

**Fase 3 — Respuesta (mes 3)**
- SOAR (Shuffle) + primeros playbooks + integración Defender XDR.
- Medir MTTR antes/después.

**Fase 4 — Inteligencia avanzada (mes 4+)**
- RAG/correlación, consulta en lenguaje natural, reducción ML de FP.

**Fase 5 — DFIR y Enterprise (a demanda)**
- Módulo forense dockerizado, migración a Kubernetes, RBAC/Vault/HA.

---

## 11. Cómo encaja el script de hardening actual

Tu `hardening_ubuntu.sh` se convierte en el **módulo de Postura/Configuración**:

- **Refactor recomendado**: portar la lógica a un **rol de Ansible**
  (`modules/hardening/`) para hacerlo declarativo, idempotente y escalable a N
  hosts. El script Bash queda como versión standalone para un único host.
- **Datos que aporta a la plataforma**: su inventario (paquetes, servicios,
  puertos) y su modo `--audit` alimentan el scoring de exposición y la correlación
  con CVEs. Es una **fuente de contexto de postura** valiosísima para la IA.
- **MCP server**: `hardening_server.py` con `run_audit(host)` y
  `get_posture(host)` para que el agente consulte el estado de hardening al
  priorizar un incidente ("¿este host ya tenía SSH endurecido?").

---

## 12. Primeros pasos accionables (esta semana)

1. Crear el repo con la estructura de la sección 3 (te dejo el scaffold listo).
2. Definir el `core/schema` OCSF mínimo (alert, host, ioc, case).
3. Levantar Compose con Redis + Postgres + Wazuh.
4. Construir **un** MCP server (VirusTotal es el más rápido) y el **agente de
   triage** de la sección 8.2.
5. Cerrar el vertical: alerta Wazuh → enriquecida → priorizada → caso. Demo.

> Regla de oro: **un vertical completo funcionando** > seis módulos a medio hacer.
> Ese primer flujo end-to-end es, además, tu mejor contenido para LinkedIn/GitHub.
