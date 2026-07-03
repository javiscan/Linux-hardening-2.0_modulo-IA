# IA + Wazuh: del hardening a un SIEM inteligente

> Cómo la IA participa REALMENTE en esta plataforma y cómo se conecta toda la
> telemetría (hardening + Suricata + auditd) dentro de Wazuh, para que el servidor
> Wazuh no solo confirme que endureciste el sistema, sino que además "vea" lo que
> pasa en la red vía Suricata y la IA te lo explique y priorice.

---

## 1. La diferencia real con el hardening anterior

El hardening solo (v1) es una **foto puntual**: aplicás controles y listo. No sabés
si mañana siguen bien, ni ves si te están atacando.

Esta plataforma con IA es un **ciclo continuo**:

1. El **hardening** emite telemetría JSON = tu **postura** (qué tan cerrado está el host).
2. **auditd (HIDS)** + **Suricata (NIDS)** generan eventos de seguridad en **tiempo real**.
3. **Wazuh** centraliza y correlaciona TODO (postura + eventos de host + eventos de red).
4. La **IA** razona sobre ese conjunto: prioriza, resume, correlaciona y recomienda.

En una analogía:
- El **hardening** te dice: *"cerré la puerta con llave"*.
- **Suricata** te dice: *"alguien está probando la cerradura desde la red"*.
- **auditd** te dice: *"dentro del host se modificó /etc/passwd"*.
- **Wazuh** une las tres cosas en un solo lugar.
- La **IA** te dice: *"esto de acá importa, es urgente, y hacé esto"*.

Esa unión **postura + amenaza** es lo que un humano tarda en cruzar y la IA hace al instante.

---

## 2. Cómo se relacionan las piezas

```
  ENDPOINT (cada servidor/workstation)
  ┌───────────────────────────────────────────────┐
  │ hardening_2.0+IA.sh -> reports/HOST/*.jsonl     │  (POSTURA / config CIS)
  │ auditd (HIDS)       -> /var/log/audit/audit.log │  (que pasa DENTRO del host)
  │ Suricata (NIDS)     -> /var/log/suricata/eve.json│ (que pasa en la RED)
  └───────────────┬───────────────────────────────┘
                  │   Wazuh Agent (recolecta las 3 fuentes)
                  ▼
        ┌───────────────────────────┐
        │   WAZUH MANAGER (SIEM)     │  decodifica + reglas + alertas
        │   + Indexer + Dashboard    │  (correlaciona postura + host + red)
        └─────────────┬─────────────┘
                      │  API de Wazuh
                      ▼
             ┌─────────────────────┐
             │   CAPA DE IA         │  triage, resumen, correlacion,
             │ (script / MCP + LLM) │  priorizacion y recomendaciones
             └─────────────────────┘
```

- **auditd = HIDS**: integridad de archivos, cambios de usuarios, uso de sudo, etc.
- **Suricata = NIDS**: escaneos, exploits, tráfico C2, firmas de ataque en la red.
- **Hardening = postura**: estado de configuración (CIS) del host.
- **Wazuh Agent** recolecta las 3 fuentes y las envía al **Manager**.
- **Wazuh Manager** decodifica, aplica reglas, genera alertas e indexa todo.
- La **IA** consume la **API de Wazuh** (o los datos indexados).

---

## 3. Wiring paso a paso

### 3.1 Wazuh Manager (servidor central)
Instalá el "all-in-one" (manager + indexer + dashboard):
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a          # instala todo en un solo servidor
```

### 3.2 Wazuh Agent en cada endpoint
```bash
# apuntando al IP de tu manager
WAZUH_MANAGER='IP_DEL_MANAGER' apt-get install wazuh-agent -y
systemctl enable --now wazuh-agent
```
> Tip: el **Módulo 2 (logging)** de la plataforma ya deja preparada la integración
> con Wazuh y las reglas de auditd, así que el endpoint llega "listo" para esto.

### 3.3 Suricata → Wazuh  (tu pregunta central)
Wazuh trae de fábrica el **decoder y ruleset para Suricata**. Solo hay que decirle
al agente que lea el `eve.json`. En `/var/ossec/etc/ossec.conf` del agente:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
Reiniciá el agente: `systemctl restart wazuh-agent`. A partir de ahí, cada alerta
de Suricata (grupo de reglas `ids`/`suricata`) llega al Manager y se ve en el dashboard.

### 3.4 auditd → Wazuh
Wazuh consume auditd de forma nativa. Como el Módulo 2 ya carga reglas CIS en
`/etc/audit/rules.d/`, esos eventos (cambios en passwd, sudo, SSH, módulos del
kernel) aparecen correlacionados automáticamente.

### 3.5 Hardening (postura) → Wazuh
Para que Wazuh también "vea" el resultado del hardening, hacé que lea el
`events.jsonl` que genera la plataforma. En `ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/linux-hardening-platform/reports/*/events_*.jsonl</location>
</localfile>
```
(Ver `integrations/wazuh/` en este repo para la plantilla lista.)
Opcional: decoders/reglas propias para que `status:"fail"` con `severity:"high"`
dispare una alerta de nivel alto en Wazuh.

---

## 4. Verificar que Wazuh "lee" Suricata

Prueba de humo (end-to-end):

1. **Generá tráfico sospechoso** contra el endpoint desde otra máquina autorizada:
   ```bash
   nmap -sS -p 1-1000 IP_DEL_ENDPOINT     # un escaneo que Suricata detecta
   ```
2. **Confirmá que Suricata lo vio** (en el endpoint):
   ```bash
   tail -f /var/log/suricata/eve.json | grep alert
   ```
3. **Confirmá que Wazuh lo recibió** (en el manager):
   ```bash
   tail -f /var/ossec/logs/alerts/alerts.json | grep -i suricata
   ```
4. **En el dashboard**: Threat Hunting / Security Events → filtrá por
   `rule.groups: ids` o `data.suricata`. Ahí ves la alerta con el host de origen.
5. **Verificá que el agente está activo** (manager):
   ```bash
   /var/ossec/bin/agent_control -l      # el endpoint debe figurar "Active"
   ```

Si los 5 pasos dan OK, tenés el flujo **Suricata → Agente → Manager → Dashboard**
funcionando. Ese es el "cien" (SIEM) leyendo la telemetría de red.

---

## 5. Dónde entra la IA (por niveles, de lo simple a lo avanzado)

**Nivel 0 — Cimiento (ya lo tenés):** telemetría JSON estandarizada. Sin datos
estructurados no hay IA útil. La plataforma ya lo produce.

**Nivel 1 — Resumen inteligente (`ai/summarize.sh`):** un script consulta la API de
Wazuh (alertas recientes) + el `events.jsonl` (postura) y con un LLM devuelve:
- un resumen en lenguaje claro del estado del endpoint,
- el top de riesgos priorizados,
- recomendaciones concretas.

Ejemplo de consulta a la API de Wazuh:
```bash
TOKEN=$(curl -sk -u user:pass -X POST "https://MANAGER:55000/security/user/authenticate" | jq -r .data.token)
curl -sk -H "Authorization: Bearer $TOKEN" "https://MANAGER:55000/alerts?limit=50&sort=-timestamp"
# -> ese JSON se le pasa al LLM junto con la postura para que resuma y priorice.
```

**Nivel 2 — Triage y reducción de falsos positivos:** un agente lee las alertas
nuevas de Wazuh, las clasifica (real / FP) y las **correlaciona con la postura**:
> Suricata detecta escaneo de puertos + el hardening dice "UFW inactivo en ese host"
> → prioridad MÁXIMA. Si UFW estuviera activo, la misma alerta baja de prioridad.

Esa correlación postura↔amenaza es el mayor valor de la IA acá.

**Nivel 3 — Agente conversacional (MCP + LLM):** un MCP Server sobre la API de
Wazuh permite preguntar en lenguaje natural:
> "¿Qué endpoints con hardening bajo están recibiendo escaneos esta semana?"

El agente traduce la pregunta a consultas Wazuh, cruza con la postura y arma el caso.

---

## 6. La diferencia, en una frase

- **Hardening anterior:** *"endurecí el sistema"* (y no sé más nada).
- **Este módulo con IA:** *"endurezco, vigilo con Suricata (red) y auditd (host),
  centralizo todo en Wazuh, y la IA me dice en lenguaje claro qué está pasando, qué
  es urgente y qué hacer — de forma continua"*.

---

## 7. Próximos pasos concretos en el repo

1. Usar `integrations/wazuh/ossec-hardening.xml` (plantilla incluida) para que Wazuh
   lea `events.jsonl` y `eve.json`.
2. Convertir `ai/summarize.sh` en un cliente real de la API de Wazuh + LLM (Nivel 1).
3. (Opcional) decoders/reglas propias para eventos de hardening en Wazuh.
4. Más adelante: MCP Server sobre Wazuh para el agente conversacional (Nivel 3),
   que conecta con la "Modular Cybersecurity Platform" (doc `ARQUITECTURA_MCP.md`).
