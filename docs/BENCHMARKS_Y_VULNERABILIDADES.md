# Score contra estándares (CIS/CVE) y punto de inflexión antes/después

> Cómo hacer que el % del hardening NO se mida contra un checklist propio, sino
> como **comparativa contra bases oficiales y auto-actualizables** (CIS, feeds de
> CVE, Microsoft), y cómo mostrar el "antes vs después" al aplicar mejoras.

---

## 1. Por qué Wazuh sigue encontrando críticas aunque endurezcas (clave)

Estás mezclando (con razón) DOS ejes diferentes. Entenderlos resuelve el 90% de la duda:

| Eje | Pregunta que responde | Se mide contra | Se cierra con |
|-----|-----------------------|----------------|---------------|
| **Configuración / Hardening** | ¿Está bien configurado el sistema? | **CIS Benchmark**, DISA STIG, baselines de Microsoft | Cambios de config (lo que hace tu script) |
| **Vulnerabilidades (CVE)** | ¿El software instalado tiene fallos conocidos? | **Feeds de CVE** (NVD, Canonical/Ubuntu, Debian, MSRC) | **Parches / actualizar versiones**, no config |

Tu hardening ataca el PRIMER eje. Las "críticas" que ve Wazuh casi siempre son del
SEGUNDO eje: paquetes desactualizados con CVEs. Por eso podés tener el sistema
perfectamente endurecido y aún así ver CVEs críticas — se cierran **parcheando**,
no configurando. Ambos ejes importan y se miden con bases distintas.

---

## 2. Las bases oficiales y auto-actualizables (no reinventes la rueda)

La recomendación de fondo: **tu plataforma NO debe inventar la base de datos**.
Debe ser un **agregador** que consulta las fuentes oficiales y reporta su resultado.

### Eje configuración (CIS)
- **Wazuh SCA (Security Configuration Assessment)**: viene con **políticas CIS**
  listas. Te da un **% de cumplimiento** por política (ej: "CIS Ubuntu 22.04: 68%").
  Se actualiza con Wazuh. *Esta es exactamente la "comparativa contra estándar" que buscás.*
- **OpenSCAP + SCAP Security Guide (SSG)**: motor oficial para evaluar perfiles
  **CIS/STIG** en el host, con reporte HTML y % de aprobados. Gratis y offline.
- **CIS-CAT** (de CIS): la herramienta oficial de CIS (Lite/Pro).

### Eje vulnerabilidades (CVE)
- **Wazuh Vulnerability Detection**: correlaciona los paquetes instalados contra
  feeds de CVE (Canonical, Debian, NVD, y **MSRC para Windows**). Te da la lista de
  CVEs por severidad. Feeds auto-actualizados por Wazuh.
- **Trivy** (Aqua): escáner de CVE muy rápido para el sistema/paquetes/contenedores.
- **debsecan** / **apt**: CVEs de paquetes Debian/Ubuntu.

### Endpoints Microsoft 365 / Windows
- **Microsoft Secure Score**: el % de postura de tu tenant M365 (equivalente a un
  "CIS score" pero de Microsoft).
- **Microsoft Defender for Endpoint — TVM** (Threat & Vulnerability Management):
  la base de vulnerabilidades y recomendaciones de Microsoft por endpoint.
- Se consultan por **API (Microsoft Graph Security)**, no por Bash.

---

## 3. La recomendación concreta para tu plataforma

Cambiá el significado del score: en vez de "% de mis checks propios", que sea:

```
Score de postura = f( % cumplimiento CIS (SCA/OpenSCAP) ,  CVEs abiertas por severidad )
```

Es decir, la plataforma **orquesta** el escaneo con herramientas oficiales y
**reporta su resultado**, más el delta antes/después. Tus módulos de hardening
siguen APLICANDO mejoras; el score las MIDE contra el estándar externo.

Ventaja: siempre actualizado (las bases las mantienen CIS/Canonical/Microsoft), y
100% defendible ante un auditor ("no es mi criterio, es CIS/CVE").

---

## 4. Cómo obtener el % contra el estándar HOY (comandos)

### 4.1 Cumplimiento CIS con OpenSCAP (en el endpoint, offline)
```bash
apt-get install -y openscap-scanner ssg-debderived   # motor + guias SSG
# Evaluar el perfil CIS y generar reporte + porcentaje
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results cis-results.xml --report cis-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
# El HTML muestra "Pass/Fail" y el % de cumplimiento.
```

### 4.2 Cumplimiento CIS con Wazuh SCA (centralizado)
- Ya viene activo. En el dashboard: **Security Configuration Assessment** →
  elegís el host → ves el **% de la política CIS** y los checks fallidos.

### 4.3 Índice de hardening con Lynis (rápido, ya integrado)
```bash
lynis audit system     # devuelve un "Hardening index" (0-100)
```
> Ojo: el índice de Lynis es su propia métrica, útil como referencia rápida, pero
> el "% oficial" para auditoría es el de CIS (OpenSCAP/SCA).

---

## 5. Escaneo de vulnerabilidades (CVE) con feed actualizado

### 5.1 Wazuh Vulnerability Detection (recomendado, centralizado)
- Activá el módulo en el manager. En el dashboard: **Vulnerability Detection** →
  ves CVEs por host y severidad (Critical/High/Medium/Low), con el CVE-ID y el paquete.

### 5.2 Trivy (en el endpoint, rápido)
```bash
# instalar trivy y escanear el sistema
trivy rootfs --severity CRITICAL,HIGH /    # lista CVEs criticas/altas del host
```

### 5.3 debsecan (Debian/Ubuntu)
```bash
apt-get install -y debsecan
debsecan --suite $(lsb_release -cs) --format detail
```

Cerrar esas CVEs = **parchear**: `apt-get upgrade` + actualizar versiones + a veces
cambiar de release. Tu Módulo 3 (patches) automatiza gran parte.

---

## 6. El "punto de inflexión": antes vs después

Esto es 100% factible y es la parte más vendible. La idea: **baseline + delta**.

1. **Baseline (antes):** antes de aplicar mejoras, se toma un snapshot con los números
   oficiales y se guarda con fecha:
   - % cumplimiento CIS (de OpenSCAP/SCA)
   - CVEs Critical / High / Medium (de Trivy/Wazuh)
2. **Aplicás las mejoras** (hardening + parches).
3. **Re-escaneo (después):** se vuelve a medir con las mismas herramientas.
4. **Delta / punto de inflexión:** el reporte muestra la comparación:

```
==== PUNTO DE INFLEXION - web-01 ====
Cumplimiento CIS:   antes 61%   ->  despues 88%   (+27)
CVE Criticas:       antes 14    ->  despues 2     (-12)
CVE Altas:          antes 33    ->  despues 9     (-24)
Fecha baseline: 2026-07-01 09:00   |   Fecha mejora: 2026-07-03 18:00
```

En Wazuh esto también se ve nativamente comparando el dashboard por rango de fechas
(las alertas de vulnerabilidad y el % de SCA a lo largo del tiempo).

---

## 7. Plan de integración en el repo (módulos nuevos)

Manteniendo el patrón modular actual, se agregan (sin tocar lo existente):

- **`modules/80-cis-compliance.sh`**: corre OpenSCAP con perfil CIS → parsea el % →
  `report_event` con el score OFICIAL. (O consulta la API de Wazuh SCA.)
- **`modules/81-vuln-scan.sh`**: corre Trivy/debsecan (o consulta Wazuh Vulnerability
  Detection) → cuenta CVEs por severidad → `report_event`.
- **`lib/report.sh`**: función `report_baseline` (guarda snapshot) y `report_delta`
  (compara baseline vs actual y muestra el "antes/después").
- **Score global** = combina % CIS + penalización por CVEs críticas, en vez del
  conteo propio actual.
- **M365/Windows**: integración aparte vía Microsoft Graph Security (Secure Score +
  Defender TVM), fuera del alcance Bash.

Resultado: el "100%" pasa a significar **"100% de cumplimiento CIS y 0 CVEs
críticas según las bases oficiales"**, siempre actualizado, con el antes/después.

---

## 8. Resumen en una frase

No hay que copiar la base de Wazuh/Microsoft: hay que **consultarla**. Tu plataforma
aplica el hardening y luego **mide el resultado contra CIS (config) y contra los
feeds de CVE (vulnerabilidades)**, guarda un baseline y te muestra el punto de
inflexión "de X críticas a Y" cada vez que mejorás.
