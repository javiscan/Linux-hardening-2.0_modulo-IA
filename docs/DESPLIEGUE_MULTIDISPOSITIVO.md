# Despliegue multi-dispositivo y publicación en GitHub

## 1. Subir el proyecto a GitHub (desde tu Linux)

1. Creá un repositorio **vacío** en https://github.com/new
   (sin README ni licencia; este proyecto ya los trae). Nombre sugerido:
   `linux-hardening-platform`.
2. En tu Linux, dentro de la carpeta del proyecto:

```bash
cd linux-hardening-platform
rm -rf .git                      # por si quedó alguno de una copia previa
git init
git add .
git commit -m "feat: Linux Hardening Platform v2.0 - framework modular con telemetria JSON"
git branch -M main
git remote add origin git@github.com:TU_USUARIO/linux-hardening-platform.git
git push -u origin main
```

> Nota: la creación del repo y el push se hacen desde tu máquina (con tus
> credenciales). No requiere nada especial: `git clone` + ejecución, como pediste.

---

## 2. ¿Qué de tu visión es factible? (respuesta corta: casi todo)

| Idea | ¿Factible? | Cómo |
|------|-----------|------|
| Correr en múltiples dispositivos | **Sí** | Modelo **agente**: instalás el framework en cada endpoint; corre local y envía telemetría al SIEM central. |
| Dejarlo en un servidor que "detecte" otros endpoints | **Sí** | (a) *Descubrimiento* con Nmap en TU subred; (b) *manager central* (SIEM) que recibe la telemetría de los agentes e inventaría. |
| Escanear otros endpoints / redes | **Sí, con límite legal** | Solo sobre **activos propios y autorizados** (allowlist de alcance). Escanear redes de terceros es ilegal. |
| Verificar que haya un EDR instalado | **Sí (ya incluido)** | Módulo `70-edr-check.sh`: detecta Wazuh, Filebeat, osquery, CrowdStrike, Defender, SentinelOne, etc. |
| Endpoints Windows | **Sí, con extensión** | Requiere un agente PowerShell + integración con Defender XDR (fuera del alcance Bash actual). |

---

## 3. Arquitectura recomendada: modelo agente + manager

```
   [Endpoint 1] --agente(local)--\
   [Endpoint 2] --agente(local)---> (telemetria JSON) --> [SIEM central: Wazuh/ELK/Splunk]
   [Endpoint N] --agente(local)--/                              |
                                                          [Dashboard + alertas]
```

- **Agente**: este mismo framework en cada host, corriendo `--audit` por cron.
- **Manager**: tu SIEM recibe los `events_*.jsonl`. La detección "de otro endpoint"
  es, en realidad, ver su telemetría llegar al manager (o su ausencia = host caído).
- **Ventaja**: escalable, sin credenciales de root remotas, y respeta el principio
  de mínimo privilegio. Es como operan Wazuh/CrowdStrike/Defender.

---

## 4. Recetas prácticas

### 4.1 Desplegar en varios hosts (desde tu servidor de gestión)

```bash
# Opcion simple (SSH). Ideal: reemplazar por un playbook Ansible.
for h in host1 host2 host3; do
  scp -r linux-hardening-platform "$h:/opt/"
  ssh "$h" "cd /opt/linux-hardening-platform && sudo ./hardening_2.0+IA.sh --audit --profile server"
done
```

### 4.2 Descubrir endpoints vivos en TU red (autorizada)

```bash
nmap -sn 192.168.1.0/24        # ping sweep: lista hosts activos de tu subred
```

### 4.3 Auditoría periódica + telemetría (cron en cada endpoint)

```bash
# /etc/cron.d/hardening-audit  -> audita cada dia a las 03:00 y envia al SIEM
0 3 * * * root /opt/linux-hardening-platform/hardening_2.0+IA.sh --audit >/dev/null 2>&1
```
(Requiere `SIEM_ENABLED=true` en `config/platform.conf`.)

### 4.4 Escaneo de vulnerabilidades desde el manager (solo alcance autorizado)

```bash
# Nmap contra un endpoint de tu inventario
nmap -sV --script vuln target-autorizado
# o OpenVAS/Nessus para un escaneo completo
```

---

## 5. Límites y buenas prácticas (importante)

- **Solo activos propios/autorizados**: cualquier escaneo o prueba debe estar en
  una allowlist de alcance ("rules of engagement"). Escanear terceros es ilegal.
- **No credenciales root remotas embebidas**: preferí el modelo agente + SSH con
  clave, o Ansible con vault para secretos.
- **Windows/EDR comercial**: se integra vía sus APIs (Defender XDR, etc.), no por
  Bash. Es la evolución natural hacia la "Modular Cybersecurity Platform".
- **La IA va al final del pipeline**: lee la telemetría centralizada, nunca en el
  camino que modifica los sistemas.
