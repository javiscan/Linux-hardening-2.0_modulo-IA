#!/usr/bin/env bash
#
# ==============================================================================
#  hardening_ubuntu.sh  -  Ubuntu / Debian Endpoint Hardening Toolkit
# ==============================================================================
#  Script interactivo de fortalecimiento (hardening) para sistemas Ubuntu y
#  Debian. Cubre SSH, logging y auditoria, parches, hardening del SO, red y DNS.
#  Alineado con buenas practicas de CIS Benchmark y NIST.
#
#  Version : 1.2.0
#  Licencia: MIT
#  Uso     : sudo ./hardening_ubuntu.sh [opciones]
#
#  IMPORTANTE
#  ----------
#  * Probar SIEMPRE en una VM o entorno controlado antes de produccion.
#  * El script realiza copias de seguridad de cada archivo antes de tocarlo.
#  * Antes de aplicar el firewall (Punto 5) se garantiza el acceso SSH para
#    evitar que te quedes bloqueado fuera del servidor.
#
#  Se entrega "tal cual", sin garantia. El uso es responsabilidad del usuario.
# ==============================================================================

set -o pipefail

# ------------------------------------------------------------------------------
# Metadatos y variables globales
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="hardening_ubuntu.sh"
readonly SCRIPT_VERSION="1.2.0"
TIMESTAMP="$(date +%Y%m%d_%H%M)"
readonly TIMESTAMP
readonly LOG_FILE="/var/log/hardening_ubuntu_${TIMESTAMP}.log"
readonly BACKUP_DIR="/root/hardening_backups_${TIMESTAMP}"
readonly INVENTORY_FILE="${BACKUP_DIR}/inventario_${TIMESTAMP}.txt"
readonly REPORT_DIR="/var/log/hardening-report"
readonly REPORT_FILE="${REPORT_DIR}/report_${TIMESTAMP}.txt"

# Modos de ejecucion (se ajustan via parametros)
DRY_RUN=false      # --dry-run : muestra lo que haria, sin aplicar
AUDIT_ONLY=false   # --audit   : solo reporta el estado actual, sin cambiar nada
ASSUME_YES=false   # --yes     : responde "si" a confirmaciones (uso con cuidado)
APPLY_ALL=false    # interno   : activo cuando se usa la opcion T (aplicar todo)

# Datos de distro (se completan en detect_distro)
DISTRO_ID="desconocido"
DISTRO_NAME="Sistema desconocido"
DISTRO_VERSION=""

# Puerto SSH detectado (se actualiza en module_ssh y module_network)
SSH_PORT="22"

# ------------------------------------------------------------------------------
# Paleta de colores (sin amarillo)
#   azul  = titulos/bordes | verde = exito | cyan = info/sugerencias
#   rojo  = error/critico  | blanco = texto destacado / prompts
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    readonly C_BLUE="\033[1;34m"
    readonly C_GREEN="\033[1;32m"
    readonly C_CYAN="\033[1;36m"
    readonly C_RED="\033[1;31m"
    readonly C_WHITE="\033[1;37m"
    readonly C_RESET="\033[0m"
else
    readonly C_BLUE="" C_GREEN="" C_CYAN="" C_RED="" C_WHITE="" C_RESET=""
fi

# ------------------------------------------------------------------------------
# Funciones de salida y logging
# ------------------------------------------------------------------------------
log() {
    local line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    if [[ "$DRY_RUN" == false ]]; then
        echo "$line" >>"$LOG_FILE" 2>/dev/null || true
    fi
}

title() { printf '\n%b===== %s =====%b\n' "$C_BLUE" "$1" "$C_RESET"; log "TITULO: $1"; }
ok()    { printf '%b[ OK ]%b %s\n'  "$C_GREEN" "$C_RESET" "$1"; log "OK: $1"; }
info()  { printf '%b[INFO]%b %s\n'  "$C_CYAN"  "$C_RESET" "$1"; log "INFO: $1"; }
warn()  { printf '%b[WARN]%b %s\n'  "$C_RED"   "$C_RESET" "$1"; log "WARN: $1"; }
err()   { printf '%b[ERR ]%b %s\n'  "$C_RED"   "$C_RESET" "$1" >&2; log "ERR: $1"; }
note()  { printf '%b%s%b\n'         "$C_WHITE" "$1" "$C_RESET"; }

# Caja explicativa didactica antes de cada accion
explain() {
    printf '%b' "$C_CYAN"
    printf '  +--------------------------------------------------------------+\n'
    printf '  | %s\n' "$@"
    printf '  +--------------------------------------------------------------+%b\n' "$C_RESET"
}

# Confirmacion interactiva. Devuelve 0 = si, 1 = no.
confirm() {
    local prompt="${1:-Continuar?}"
    if [[ "$ASSUME_YES" == true ]]; then return 0; fi
    if [[ "$AUDIT_ONLY" == true ]]; then return 1; fi
    local answer
    read -r -p "$(printf '%b  %s [s/N]: %b' "$C_WHITE" "$prompt" "$C_RESET")" answer
    [[ "$answer" =~ ^([sS][iI]?|[yY])$ ]]
}

# Ejecuta un comando respetando dry-run / audit.
run() {
    if [[ "$DRY_RUN" == true || "$AUDIT_ONLY" == true ]]; then
        printf '%b[SIMULADO]%b %s\n' "$C_CYAN" "$C_RESET" "$*"
        return 0
    fi
    "$@"
}

# ¿Estamos en modo "solo lectura"? (dry-run o audit)
read_only_mode() { [[ "$DRY_RUN" == true || "$AUDIT_ONLY" == true ]]; }

# Navegacion al terminar un modulo: continuar / menu principal / salir.
# $1 = nombre de la funcion del siguiente modulo (vacio si es el ultimo)
nav_menu() {
    local next_fn="${1:-}"
    # En modos no interactivos o apply_all, no pausar
    if [[ "$ASSUME_YES" == true || "$APPLY_ALL" == true ]]; then
        return 0
    fi
    printf '\n%b  ┌──────────────────────────────────────────┐%b\n' "$C_CYAN" "$C_RESET"
    [[ -n "$next_fn" ]] && \
        printf '%b  │  [C]  Continuar al siguiente punto       │%b\n' "$C_WHITE" "$C_RESET"
    printf '%b  │  [M]  Volver al menu principal           │%b\n' "$C_WHITE" "$C_RESET"
    printf '%b  │  [S]  Salir del script                   │%b\n' "$C_WHITE" "$C_RESET"
    printf '%b  └──────────────────────────────────────────┘%b\n' "$C_CYAN" "$C_RESET"
    local opt
    read -r -p "$(printf '%b  Seleccion [%s]: %b' "$C_WHITE" "${next_fn:+C/}M/S" "$C_RESET")" opt
    case "${opt^^}" in
        C) [[ -n "$next_fn" ]] && "$next_fn" ;;
        S) info "Saliendo. Log: ${LOG_FILE}"; exit 0 ;;
        *) : ;;   # M o cualquier otra: vuelve al menu
    esac
}

# ------------------------------------------------------------------------------
# Utilidades de sistema
# ------------------------------------------------------------------------------
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "Este script debe ejecutarse como root: sudo ./${SCRIPT_NAME}"
        exit 1
    fi
}

detect_distro() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-desconocido}"
        DISTRO_NAME="${PRETTY_NAME:-$NAME}"
        DISTRO_VERSION="${VERSION_ID:-}"
    fi
    case "$DISTRO_ID" in
        ubuntu|debian) : ;;
        *)
            warn "Distro detectada: ${DISTRO_NAME}. Este script esta pensado para Ubuntu/Debian."
            confirm "Deseas continuar de todas formas?" || exit 0
            ;;
    esac
}

ensure_backup_dir() {
    if read_only_mode; then return 0; fi
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    fi
}

ensure_report_dir() {
    if read_only_mode; then return 0; fi
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR" && chmod 750 "$REPORT_DIR"
    fi
}

# Copia de seguridad con fecha/hora: archivo_backup_YYYYMMDD_HHMM.bak
backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    if read_only_mode; then
        info "Se respaldaria: $file"
        return 0
    fi
    ensure_backup_dir
    local base dest
    base="$(basename "$file")"
    dest="${BACKUP_DIR}/${base}_backup_${TIMESTAMP}.bak"
    cp -p "$file" "$dest"
    printf '%b[BACKUP]%b %s -> %b%s%b\n' "$C_CYAN" "$C_RESET" "$file" "$C_CYAN" "$dest" "$C_RESET"
    log "BACKUP: $file -> $dest"
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

# Inserta o reemplaza una linea de config. Soporta dos formatos:
#   - Estilo sshd/etc: "Clave valor"  (clave SIN signo igual, separador espacio)
#   - Estilo systemd:  "Clave=valor"  (clave termina con "=", sin espacio tras ella)
set_config_kv() {
    local file="$1" key="$2" value="$3"
    if read_only_mode; then
        if [[ "$key" == *= ]]; then
            info "Se estableceria en ${file}: ${key}${value}"
        else
            info "Se estableceria en ${file}: ${key} ${value}"
        fi
        return 0
    fi
    if [[ "$key" == *= ]]; then
        if grep -Eq "^\s*#?\s*${key}" "$file"; then
            sed -i -E "s|^\s*#?\s*${key}.*|${key}${value}|" "$file"
        else
            echo "${key}${value}" >>"$file"
        fi
    else
        if grep -Eq "^\s*#?\s*${key}\b" "$file"; then
            sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${value}|" "$file"
        else
            echo "${key} ${value}" >>"$file"
        fi
    fi
}

# ==============================================================================
# MODULO 0  -  Prerrequisitos
# ==============================================================================
readonly PREREQ_TOOLS=(
    "auditd:Auditoria del sistema (auditd)"
    "suricata:IDS/IPS de red (Suricata)"
    "fail2ban:Bloqueo de fuerza bruta (Fail2ban)"
    "lynis:Auditoria de hardening (Lynis)"
    "nmap:Escaneo y descubrimiento de red (Nmap)"
    "ufw:Firewall sencillo (UFW)"
    "unattended-upgrades:Parches automaticos de seguridad"
)

module_prereqs() {
    title "MODULO 0 - Prerrequisitos"
    explain "Estas herramientas potencian el hardening (IDS, auditoria, firewall," \
            "escaneo). Aqui ves cuales estan instaladas y puedes instalarlas."

    local faltantes=()
    local entry pkg desc
    for entry in "${PREREQ_TOOLS[@]}"; do
        pkg="${entry%%:*}"; desc="${entry#*:}"
        if pkg_installed "$pkg"; then
            printf '  %b[OK]%b   %-26s %s\n' "$C_GREEN" "$C_RESET" "$pkg" "$desc"
        else
            printf '  %b[FALTA]%b %-24s %s\n' "$C_RED" "$C_RESET" "$pkg" "$desc"
            faltantes+=("$pkg")
        fi
    done

    if [[ ${#faltantes[@]} -eq 0 ]]; then
        ok "Todas las herramientas recomendadas estan instaladas."
        nav_menu "module_ssh"
        return 0
    fi
    if read_only_mode; then
        info "Faltan: ${faltantes[*]} (no se instala nada en modo audit/dry-run)."
        nav_menu "module_ssh"
        return 0
    fi

    printf '\n'
    note "  [T] Instalar todo   [E] Elegir una por una   [N] Continuar sin instalar"
    local choice
    read -r -p "$(printf '%b  Seleccion [T/E/N]: %b' "$C_WHITE" "$C_RESET")" choice
    case "${choice^^}" in
        T)
            run apt-get update -y
            run apt-get install -y "${faltantes[@]}" && ok "Herramientas instaladas."
            ;;
        E)
            run apt-get update -y
            local p
            for p in "${faltantes[@]}"; do
                if confirm "Instalar ${p}?"; then
                    run apt-get install -y "$p" && ok "${p} instalado."
                fi
            done
            ;;
        *) info "Se continua sin instalar herramientas adicionales." ;;
    esac
    nav_menu "module_ssh"
}

# ==============================================================================
# PUNTO 1  -  Hardening de SSH
# ==============================================================================
module_ssh() {
    title "PUNTO 1 - Hardening de SSH"
    explain "SSH es la puerta de entrada remota al servidor. Aqui la endurecemos:" \
            "deshabilitamos el login de root, podemos cambiar el puerto y exigir" \
            "autenticacion por clave publica. Mal configurado, es el vector #1."

    local sshd="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd" ]]; then
        warn "No se encontro ${sshd}. Esta instalado el servidor SSH (openssh-server)?"
        nav_menu "module_logging"
        return 0
    fi

    local current_port
    current_port="$(grep -Ei '^\s*Port\s+' "$sshd" | awk '{print $2}' | head -n1)"
    SSH_PORT="${current_port:-22}"
    info "Puerto SSH actual: ${SSH_PORT}"

    if [[ "$AUDIT_ONLY" == true ]]; then
        info "PermitRootLogin      : $(grep -Ei '^\s*PermitRootLogin' "$sshd" | tail -n1 || echo 'no definido')"
        info "PasswordAuth         : $(grep -Ei '^\s*PasswordAuthentication' "$sshd" | tail -n1 || echo 'no definido')"
        info "MaxAuthTries         : $(grep -Ei '^\s*MaxAuthTries' "$sshd" | tail -n1 || echo 'no definido')"
        nav_menu "module_logging"
        return 0
    fi

    backup_file "$sshd"

    # --- Cambio de puerto (opcional) ---
    explain "Cambiar el puerto por defecto (22) reduce el ruido de bots y escaneos." \
            "Sugerencias: 2222, 9022, 10022, 49222 (rango alto, menos conflictos)."
    if confirm "Deseas cambiar el puerto SSH (actual: ${SSH_PORT})?"; then
        local new_port
        read -r -p "$(printf '%b  Nuevo puerto (ej. 2222): %b' "$C_WHITE" "$C_RESET")" new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1 && new_port <= 65535 )); then
            if command -v ufw >/dev/null 2>&1; then
                run ufw allow "${new_port}/tcp"
                info "Anti-bloqueo: ${new_port}/tcp abierto en UFW antes del cambio."
            fi
            set_config_kv "$sshd" "Port" "$new_port"
            SSH_PORT="$new_port"
            ok "Puerto SSH configurado en ${new_port}."
            warn "NO cierres esta sesion. Abre OTRA terminal y prueba: ssh -p ${new_port} usuario@host"
        else
            warn "Puerto invalido. Se mantiene ${SSH_PORT}."
        fi
    fi

    # --- Metodo de autenticacion ---
    explain "La clave publica es mucho mas segura que la contraseña. Si eliges" \
            "'solo clave', asegurate de tener tu clave ya instalada (~/.ssh/authorized_keys)."
    local auth_choice
    read -r -p "$(printf '%b  Autenticacion: [1] solo clave publica  [2] permitir contraseña: %b' "$C_WHITE" "$C_RESET")" auth_choice
    if [[ "$auth_choice" == "1" ]]; then
        local has_key=false f
        for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
            [[ -s "$f" ]] && has_key=true
        done
        if [[ "$has_key" == false ]]; then
            warn "No se detectaron claves autorizadas. Desactivar la contraseña podria bloquearte."
            if confirm "Aun asi, deshabilitar autenticacion por contraseña?"; then
                set_config_kv "$sshd" "PasswordAuthentication" "no"
            else
                info "Se mantiene la autenticacion por contraseña."
            fi
        else
            set_config_kv "$sshd" "PasswordAuthentication" "no"
            ok "Autenticacion por contraseña deshabilitada."
        fi
    else
        info "Se mantiene la autenticacion por contraseña habilitada."
    fi

    # --- Endurecimiento base ---
    set_config_kv "$sshd" "PermitRootLogin" "no"
    set_config_kv "$sshd" "X11Forwarding" "no"
    set_config_kv "$sshd" "MaxAuthTries" "3"
    set_config_kv "$sshd" "LoginGraceTime" "30"
    set_config_kv "$sshd" "ClientAliveInterval" "300"
    set_config_kv "$sshd" "ClientAliveCountMax" "2"
    set_config_kv "$sshd" "Protocol" "2"

    if read_only_mode; then
        info "Se validaria y recargaria sshd."
    else
        if sshd -t 2>>"$LOG_FILE"; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
            ok "SSH endurecido y servicio recargado."
        else
            err "La configuracion de sshd tiene errores. Restaurando el backup original..."
            local sshd_bak="${BACKUP_DIR}/sshd_config_backup_${TIMESTAMP}.bak"
            if [[ -f "$sshd_bak" ]]; then
                cp -p "$sshd_bak" "$sshd"
                ok "Backup restaurado: ${sshd_bak}. Configuracion SSH sin cambios."
            else
                err "No se encontro el backup. Revisa ${sshd} manualmente."
            fi
        fi
    fi
    warn "RECORDATORIO: verifica una nueva conexion SSH en otra terminal ANTES de cerrar esta."
    nav_menu "module_logging"
}

# ==============================================================================
# PUNTO 2  -  Logging, auditoria y SIEM  (interactivo por herramienta)
# ==============================================================================
module_logging() {
    title "PUNTO 2 - Logging, auditoria y SIEM"
    explain "Si no registras, no puedes investigar. Configuramos auditd con reglas" \
            "CIS, persistencia de logs con retencion de 90 dias, y conectamos" \
            "opcionalmente a un SIEM para centralizar y correlacionar alertas."

    if [[ "$AUDIT_ONLY" == true ]]; then
        info "auditd activo     : $(systemctl is-active auditd 2>/dev/null || echo 'no')"
        info "Reglas cargadas   : $(auditctl -l 2>/dev/null | wc -l) lineas"
        info "journald Storage  : $(grep -Ei '^\s*Storage=' /etc/systemd/journald.conf 2>/dev/null | tail -n1 || echo 'por defecto')"
        nav_menu "module_patches"
        return 0
    fi

    # --- auditd ---
    if ! pkg_installed auditd; then
        if confirm "auditd no esta instalado. Instalarlo ahora?"; then
            run apt-get install -y auditd audispd-plugins
        else
            info "Se omite la configuracion de auditd."
            nav_menu "module_patches"
            return 0
        fi
    fi

    local jconf="/etc/systemd/journald.conf"
    if [[ -f "$jconf" ]]; then
        backup_file "$jconf"
        set_config_kv "$jconf" "Storage=" "persistent"
    fi

    local rules="/etc/audit/rules.d/hardening.rules"
    explain "Reglas que vigilan eventos criticos: cambios en cuentas, uso de sudo," \
            "accesos a SSH, carga de modulos del kernel y accesos denegados (CIS)."
    if read_only_mode; then
        info "Se escribirian reglas CIS en ${rules}"
    else
        cat >"$rules" <<'EOF'
## Reglas de auditoria - hardening (CIS Benchmark)
-D
-b 8192
-f 1
## Identidad y cuentas
-w /etc/passwd -p wa -k identidad
-w /etc/group -p wa -k identidad
-w /etc/shadow -p wa -k identidad
-w /etc/gshadow -p wa -k identidad
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
## Autenticacion y SSH
-w /var/log/auth.log -p wa -k autenticacion
-w /etc/ssh/sshd_config -p wa -k ssh
## Cambios de privilegios
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k escalada
## Modulos del kernel
-w /sbin/insmod -p x -k modulos
-w /sbin/rmmod -p x -k modulos
-w /sbin/modprobe -p x -k modulos
-a always,exit -F arch=b64 -S init_module -S delete_module -k modulos
## Accesos denegados
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k acceso_denegado
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM  -k acceso_denegado
## Cambios de fecha/hora
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k tiempo
## Reglas inmutables (requiere reinicio para modificarlas)
-e 2
EOF
        augenrules --load 2>>"$LOG_FILE" || true
        systemctl enable --now auditd 2>>"$LOG_FILE" || true
        ok "Reglas de auditoria CIS cargadas y auditd habilitado."
    fi

    local lr="/etc/logrotate.d/hardening"
    if read_only_mode; then
        info "Se configuraria logrotate con 90 dias de retencion."
    else
        cat >"$lr" <<'EOF'
/var/log/auth.log /var/log/syslog {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
}
EOF
        ok "Retencion de logs configurada (90 dias)."
    fi

    # --- SIEM: interactivo por herramienta ---
    _logging_siem_interactive

    nav_menu "module_patches"
}

# Detecta y ofrece configurar cada integracion SIEM de forma independiente
_logging_siem_interactive() {
    printf '\n%b  ─── Integracion con SIEM ───────────────────────────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "Un SIEM centraliza logs de todos tus equipos y permite detectar" \
            "amenazas por correlacion. Cada opcion se configura por separado."

    printf '\n%b  Estado actual de integraciones:%b\n\n' "$C_WHITE" "$C_RESET"
    _siem_status_line "Wazuh agent"        "$(pkg_installed wazuh-agent && echo true || echo false)"
    _siem_status_line "rsyslog (Graylog)"  "$(command -v rsyslog >/dev/null 2>&1 && echo true || echo false)"
    _siem_status_line "Filebeat (ELK)"     "$(pkg_installed filebeat && echo true || echo false)"
    _siem_status_line "Splunk UF"          "$(command -v splunk >/dev/null 2>&1 && echo true || echo false)"
    printf '\n'

    if confirm "Configurar integracion con Wazuh?"; then
        _siem_wazuh
    fi
    if confirm "Configurar rsyslog para reenvio a Graylog/syslog remoto?"; then
        _siem_graylog
    fi
    if confirm "Configurar Filebeat para ELK (Elasticsearch/Logstash)?"; then
        _siem_filebeat
    fi
    if confirm "Ver instrucciones para Splunk Universal Forwarder?"; then
        _siem_splunk_instructions
    fi
}

_siem_status_line() {
    local name="$1" installed="$2"
    if [[ "$installed" == true ]]; then
        printf '  %b[INSTALADO]%b  %s\n' "$C_GREEN" "$C_RESET" "$name"
    else
        printf '  %b[NO INST. ]%b  %s\n' "$C_RED"   "$C_RESET" "$name"
    fi
}

_siem_wazuh() {
    if pkg_installed wazuh-agent; then
        ok "Wazuh agent ya esta instalado."
        local wazuh_state
        wazuh_state="$(systemctl is-active wazuh-agent 2>/dev/null || echo 'inactivo')"
        info "Estado actual: ${wazuh_state}"
        if confirm "Reiniciar el agente Wazuh?"; then
            run systemctl restart wazuh-agent 2>/dev/null || true
            ok "Wazuh agent reiniciado."
        fi
        return 0
    fi
    explain "Wazuh es un SIEM open-source completo (fork de OSSEC). El agente envia" \
            "logs, alertas FIM y resultados de compliance al Wazuh Manager central."
    local manager_ip
    read -r -p "$(printf '%b  IP del Wazuh Manager (vacio para omitir): %b' "$C_WHITE" "$C_RESET")" manager_ip
    [[ -z "$manager_ip" ]] && info "Se omite la instalacion de Wazuh agent." && return 0
    if read_only_mode; then
        info "Se instalaria wazuh-agent apuntando a ${manager_ip}."
        return 0
    fi
    info "Agregando repositorio oficial de Wazuh..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -y >>"$LOG_FILE" 2>&1 || true
    WAZUH_MANAGER="${manager_ip}" apt-get install -y wazuh-agent >>"$LOG_FILE" 2>&1 || true
    systemctl enable --now wazuh-agent 2>>"$LOG_FILE" || true
    ok "Wazuh agent instalado y apuntando a ${manager_ip}."
}

_siem_graylog() {
    explain "rsyslog puede reenviar en tiempo real todos los logs del sistema a un" \
            "servidor Graylog o cualquier receptor syslog remoto (UDP/TCP 514)."
    local gl_ip
    read -r -p "$(printf '%b  IP del servidor Graylog/syslog: %b' "$C_WHITE" "$C_RESET")" gl_ip
    [[ -z "$gl_ip" ]] && info "Se omite la configuracion de rsyslog." && return 0
    if ! read_only_mode; then
        echo "*.* @@${gl_ip}:514" > /etc/rsyslog.d/90-siem.conf
        systemctl restart rsyslog 2>>"$LOG_FILE" || true
        ok "rsyslog configurado: reenvia todos los logs a ${gl_ip}:514 (TCP)."
    else
        info "Se configuraria rsyslog → ${gl_ip}:514."
    fi
}

_siem_filebeat() {
    explain "Filebeat envia logs a Elasticsearch o Logstash. Requiere un cluster" \
            "ELK operativo. Ideal para equipos que ya tienen ELK desplegado."
    if ! pkg_installed filebeat; then
        if confirm "Instalar Filebeat?"; then
            run apt-get install -y filebeat
        else
            info "Se omite la configuracion de Filebeat."; return 0
        fi
    else
        ok "Filebeat ya esta instalado."
    fi
    local elk_host
    read -r -p "$(printf '%b  Host del servidor ELK (IP o hostname, vacio para omitir): %b' "$C_WHITE" "$C_RESET")" elk_host
    [[ -z "$elk_host" ]] && info "Filebeat instalado pero sin configurar destino." && return 0
    if ! read_only_mode; then
        sed -i "s|localhost:9200|${elk_host}:9200|g" /etc/filebeat/filebeat.yml 2>/dev/null || true
        systemctl enable --now filebeat 2>>"$LOG_FILE" || true
        ok "Filebeat configurado hacia ${elk_host}:9200 y habilitado."
    else
        info "Se configuraria Filebeat → ${elk_host}:9200."
    fi
}

_siem_splunk_instructions() {
    note ""
    note "  Splunk Universal Forwarder — instrucciones manuales:"
    note "  1. Crear cuenta gratuita en: https://www.splunk.com"
    note "  2. Descargar el UF para Linux desde: splunk.com/download/universalforwarder"
    note "  3. Instalar: dpkg -i splunkforwarder-*.deb"
    note "  4. Agregar indexer: /opt/splunkforwarder/bin/splunk add forward-server IP:9997"
    note "  5. Iniciar: /opt/splunkforwarder/bin/splunk start --accept-license"
    note ""
}

# ==============================================================================
# PUNTO 3  -  Parches y vulnerabilidades  (con niveles y reporte)
# ==============================================================================
module_patches() {
    title "PUNTO 3 - Parches y gestion de vulnerabilidades"
    explain "El software sin parches es el vector de ataque mas comun. Actualizamos" \
            "el sistema, verificamos herramientas de seguridad y generamos un reporte" \
            "detallado guardado en ${REPORT_DIR}/."

    if [[ "$AUDIT_ONLY" == true ]]; then
        local pending
        pending="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)"
        info "Actualizaciones pendientes: ${pending} paquetes"
        nav_menu "module_os"
        return 0
    fi

    # --- Nivel de profundidad ---
    printf '\n%b  Nivel de actualizacion:%b\n' "$C_WHITE" "$C_RESET"
    note "  [1]  Basico    — solo parches de seguridad (rapido y conservador)"
    note "  [2]  Avanzado  — todas las actualizaciones + herramientas adicionales"
    local depth
    read -r -p "$(printf '%b  Seleccion [1/2]: %b' "$C_WHITE" "$C_RESET")" depth

    run apt-get update -y

    case "$depth" in
        2)
            if confirm "Aplicar TODAS las actualizaciones disponibles (incluyendo kernel)?"; then
                run apt-get dist-upgrade -y
                ok "Actualizacion completa del sistema aplicada."
            fi
            ;;
        *)
            if confirm "Aplicar actualizaciones de seguridad?"; then
                run apt-get upgrade -y
                ok "Actualizaciones de seguridad aplicadas."
            fi
            ;;
    esac

    # --- unattended-upgrades ---
    if ! pkg_installed unattended-upgrades; then
        if confirm "Habilitar parches automaticos de seguridad (unattended-upgrades)?"; then
            run apt-get install -y unattended-upgrades
        fi
    fi
    if pkg_installed unattended-upgrades && ! read_only_mode; then
        cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        ok "Parches de seguridad automaticos habilitados."
    fi

    # --- Herramientas de seguridad (segun nivel) ---
    _patches_security_tools "$depth"

    # --- Inventario del sistema ---
    ensure_backup_dir
    if ! read_only_mode; then
        {
            echo "=== Inventario ${TIMESTAMP} (${DISTRO_NAME}) ==="
            echo; echo "--- Paquetes instalados ---"; dpkg -l 2>/dev/null
            echo; echo "--- Servicios activos ---";   systemctl list-units --type=service --state=running 2>/dev/null
            echo; echo "--- Puertos en escucha ---";  ss -tulpn 2>/dev/null
        } >"$INVENTORY_FILE" 2>/dev/null
        ok "Inventario guardado en: ${INVENTORY_FILE}"
    else
        info "Se generaria inventario en: ${INVENTORY_FILE}"
    fi

    # --- Lynis ---
    if pkg_installed lynis; then
        if confirm "Ejecutar auditoria Lynis ahora (puede tardar unos minutos)?"; then
            run lynis audit system --quick
        fi
    else
        info "Lynis no instalado (el Modulo 0 puede instalarlo)."
    fi

    # --- Generar reporte ---
    _patches_generate_report "$depth"

    nav_menu "module_os"
}

_patches_security_tools() {
    local depth="${1:-1}"
    printf '\n%b  Herramientas de seguridad:%b\n\n' "$C_WHITE" "$C_RESET"

    local -a tools_basico=(
        "fail2ban:Bloqueo automatico de fuerza bruta"
        "ufw:Firewall sencillo (UFW)"
        "auditd:Auditoria de eventos del sistema"
        "unattended-upgrades:Parches de seguridad automaticos"
    )
    local -a tools_avanzado=(
        "lynis:Auditoria de hardening y compliance"
        "rkhunter:Detector de rootkits"
        "chkrootkit:Detector de rootkits (alternativo)"
        "aide:Monitor de integridad de archivos"
        "nmap:Escaner de puertos y red"
        "suricata:IDS/IPS de red"
    )

    local -a tools=("${tools_basico[@]}")
    [[ "$depth" == "2" ]] && tools=("${tools_basico[@]}" "${tools_avanzado[@]}")

    local faltantes=()
    local entry pkg desc
    for entry in "${tools[@]}"; do
        pkg="${entry%%:*}"; desc="${entry#*:}"
        if pkg_installed "$pkg"; then
            printf '  %b[OK]%b   %-26s %s\n' "$C_GREEN" "$C_RESET" "$pkg" "$desc"
        else
            printf '  %b[FALTA]%b %-24s %s\n' "$C_RED" "$C_RESET" "$pkg" "$desc"
            faltantes+=("$pkg")
        fi
    done

    [[ ${#faltantes[@]} -eq 0 ]] && ok "Todas las herramientas de seguridad estan instaladas." && return 0
    read_only_mode && info "Faltarian instalar: ${faltantes[*]}" && return 0

    printf '\n'
    note "  [T] Instalar todo   [E] Elegir una por una   [N] Omitir"
    local choice
    read -r -p "$(printf '%b  Seleccion [T/E/N]: %b' "$C_WHITE" "$C_RESET")" choice
    case "${choice^^}" in
        T) run apt-get install -y "${faltantes[@]}" && ok "Herramientas instaladas." ;;
        E)
            local p
            for p in "${faltantes[@]}"; do
                confirm "Instalar ${p}?" && run apt-get install -y "$p" && ok "${p} instalado."
            done
            ;;
        *) info "Se omite la instalacion de herramientas adicionales." ;;
    esac
}

_patches_generate_report() {
    local depth="${1:-1}"
    ensure_report_dir
    if read_only_mode; then
        info "Se generaria reporte en: ${REPORT_FILE}"
        return 0
    fi
    local pending hostname_val
    pending="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)"
    hostname_val="$(hostname 2>/dev/null || echo 'desconocido')"

    {
        echo "============================================================"
        echo "  REPORTE DE SEGURIDAD — Hardening Toolkit v${SCRIPT_VERSION}"
        echo "  Fecha    : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Hostname : ${hostname_val}"
        echo "  Sistema  : ${DISTRO_NAME} ${DISTRO_VERSION}"
        echo "  Nivel    : $([ "$depth" = "2" ] && echo "Avanzado" || echo "Basico")"
        echo "============================================================"
        echo ""
        echo "--- ACTUALIZACIONES PENDIENTES ---"
        printf '  Paquetes por actualizar: %s\n' "$pending"
        apt-get -s upgrade 2>/dev/null | grep '^Inst' | head -20 || true
        echo ""
        echo "--- HERRAMIENTAS DE SEGURIDAD ---"
        local tools=(fail2ban ufw auditd lynis rkhunter chkrootkit aide nmap suricata unattended-upgrades)
        local t
        for t in "${tools[@]}"; do
            if pkg_installed "$t"; then
                printf '  [OK]    %s\n' "$t"
            else
                printf '  [FALTA] %s\n' "$t"
            fi
        done
        echo ""
        echo "--- SERVICIOS EN ESCUCHA ---"
        ss -tulpn 2>/dev/null || true
        echo ""
        echo "--- FIREWALL (UFW) ---"
        ufw status 2>/dev/null || echo "  UFW no disponible"
        echo ""
        echo "============================================================"
    } >"$REPORT_FILE" 2>/dev/null
    ok "Reporte guardado en: ${REPORT_FILE}"
    printf '%b[INFO]%b Actualizaciones pendientes: %s paquetes\n' "$C_CYAN" "$C_RESET" "$pending"
}

# ==============================================================================
# PUNTO 4  -  Hardening del SO  (confirmacion por grupo)
# ==============================================================================
module_os() {
    title "PUNTO 4 - Hardening del sistema operativo"
    explain "Reducimos la superficie de ataque en cuatro grupos independientes:" \
            "servicios peligrosos, parametros sysctl de red, parametros sysctl de" \
            "kernel, permisos de archivos criticos y modulos del kernel en blacklist."

    if [[ "$AUDIT_ONLY" == true ]]; then
        info "ASLR (kernel.randomize_va_space) : $(sysctl -n kernel.randomize_va_space 2>/dev/null)"
        info "IP forwarding                    : $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
        info "ptrace scope                     : $(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)"
        nav_menu "module_network"
        return 0
    fi

    _os_grupo_servicios
    _os_grupo_sysctl_red
    _os_grupo_sysctl_kernel
    _os_grupo_permisos
    _os_grupo_modulos

    nav_menu "module_network"
}

# Grupo A: Servicios peligrosos o innecesarios
_os_grupo_servicios() {
    printf '\n%b  ─── GRUPO A: Servicios peligrosos ──────────────────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "Cada servicio activo es una posible via de entrada. Deshabilitar lo" \
            "que no usas activamente reduce la superficie de ataque del servidor."

    local -a svc_list=(
        "cups:Servidor de impresion (raramente necesario en servidores)"
        "bluetooth:Bluetooth (innecesario en la mayoria de servidores)"
        "telnet:Telnet (inseguro, sin cifrado — reemplazado por SSH)"
        "rsh-server:RSH (inseguro, sin cifrado)"
        "vsftpd:FTP (inseguro — preferir SFTP sobre SSH)"
        "avahi-daemon:mDNS/Bonjour (descubrimiento local, innecesario en servidores)"
        "xinetd:Super-servidor inetd (obsoleto)"
    )

    local entry svc desc active
    for entry in "${svc_list[@]}"; do
        svc="${entry%%:*}"; desc="${entry#*:}"
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            active="$(systemctl is-active "$svc" 2>/dev/null || echo 'inactivo')"
            printf '\n  %b[%s]%b  %s\n' "$C_WHITE" "${active^^}" "$C_RESET" "$svc"
            printf '           %s\n' "$desc"
            if [[ "$active" != "inactive" && "$active" != "failed" ]]; then
                if confirm "  Deshabilitar '${svc}'?"; then
                    run systemctl disable --now "$svc" 2>/dev/null || true
                    ok "${svc} deshabilitado."
                fi
            else
                info "  '${svc}' ya esta inactivo."
            fi
        fi
    done
}

# Grupo B: Parametros sysctl de red (CIS)
_os_grupo_sysctl_red() {
    printf '\n%b  ─── GRUPO B: Parametros sysctl de red (CIS) ────────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "Estos parametros endurecen la pila de red: SYN cookies (anti-DDoS)," \
            "filtrado anti-spoofing, bloqueo de source routing y ICMP peligrosos." \
            "Se escriben en /etc/sysctl.d/99-hardening-red.conf y son persistentes."

    local -a params=(
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.send_redirects=0"
        "net.ipv4.conf.default.send_redirects=0"
        "net.ipv4.conf.all.log_martians=1"
        "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.ip_forward=0"
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_ra=0"
    )

    printf '\n'
    _os_mostrar_sysctl "${params[@]}"

    if confirm "  Aplicar los ${#params[@]} parametros de red sysctl CIS?"; then
        _os_aplicar_sysctl "red" "${params[@]}"
    fi
}

# Grupo C: Parametros sysctl del kernel (CIS)
_os_grupo_sysctl_kernel() {
    printf '\n%b  ─── GRUPO C: Parametros sysctl del kernel (CIS) ────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "ASLR (anti-exploit), restriccion de punteros de kernel (kptr_restrict)," \
            "proteccion de ptrace, prevencion de volcados de memoria y restriccion" \
            "del acceso a mensajes del kernel (dmesg)."

    local -a params=(
        "kernel.randomize_va_space=2"
        "kernel.kptr_restrict=2"
        "kernel.dmesg_restrict=1"
        "kernel.yama.ptrace_scope=1"
        "fs.suid_dumpable=0"
        "fs.protected_hardlinks=1"
        "fs.protected_symlinks=1"
    )

    printf '\n'
    _os_mostrar_sysctl "${params[@]}"

    if confirm "  Aplicar los ${#params[@]} parametros de kernel sysctl CIS?"; then
        _os_aplicar_sysctl "kernel" "${params[@]}"
    fi
}

# Muestra el estado actual vs esperado de cada parametro sysctl
_os_mostrar_sysctl() {
    local p key expected current
    for p in "$@"; do
        key="${p%%=*}"; expected="${p#*=}"
        current="$(sysctl -n "$key" 2>/dev/null || echo '?')"
        if [[ "$current" == "$expected" ]]; then
            printf '  %b[OK ]%b %-45s = %s\n' "$C_GREEN" "$C_RESET" "$key" "$current"
        else
            printf '  %b[MOD]%b %-45s %s → %b%s%b\n' \
                "$C_RED" "$C_RESET" "$key" "$current" "$C_WHITE" "$expected" "$C_RESET"
        fi
    done
}

# Escribe los parametros en el archivo drop-in correspondiente y los aplica
_os_aplicar_sysctl() {
    local grupo="$1"; shift
    local sysctl_file="/etc/sysctl.d/99-hardening-${grupo}.conf"
    if read_only_mode; then
        info "Se escribirian parametros en ${sysctl_file}"
        return 0
    fi
    local p key value
    : > "$sysctl_file"
    for p in "$@"; do
        key="${p%%=*}"; value="${p#*=}"
        printf '%s = %s\n' "$key" "$value" >> "$sysctl_file"
    done
    sysctl --system >>"$LOG_FILE" 2>&1 || true
    ok "Parametros sysctl (${grupo}) aplicados en ${sysctl_file}."
}

# Grupo D: Permisos de archivos criticos
_os_grupo_permisos() {
    printf '\n%b  ─── GRUPO D: Permisos de archivos criticos ─────────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "Permisos incorrectos permiten a usuarios no autorizados leer contrasenas" \
            "o modificar configuraciones del sistema. Se muestra el estado actual."

    local -a perm_list=(
        "644:/etc/passwd:Lectura para todos, solo root puede escribir"
        "644:/etc/group:Lectura para todos, solo root puede escribir"
        "640:/etc/shadow:Solo root y grupo shadow pueden leer las contrasenas"
        "640:/etc/gshadow:Solo root y grupo shadow"
        "600:/etc/ssh/sshd_config:Solo root puede leer la configuracion SSH"
        "600:/boot/grub/grub.cfg:Solo root puede leer el bootloader"
        "700:/etc/cron.d:Solo root accede a las tareas programadas"
        "700:/etc/cron.daily:Solo root accede a cron diario"
        "700:/etc/cron.hourly:Solo root accede a cron por hora"
    )

    local entry mode file desc current_mode needs_fix=false
    printf '\n'
    for entry in "${perm_list[@]}"; do
        mode="${entry%%:*}"; entry="${entry#*:}"
        file="${entry%%:*}"; desc="${entry#*:}"
        [[ -e "$file" ]] || continue
        current_mode="$(stat -c '%a' "$file" 2>/dev/null || echo '???')"
        if [[ "$current_mode" == "$mode" ]]; then
            printf '  %b[OK ]%b %-30s (%s)\n' "$C_GREEN" "$C_RESET" "$file" "$mode"
        else
            printf '  %b[FIX]%b %-30s %s → %b%s%b  %s\n' \
                "$C_RED" "$C_RESET" "$file" "$current_mode" "$C_WHITE" "$mode" "$C_RESET" "$desc"
            needs_fix=true
        fi
    done

    if [[ "$needs_fix" == true ]]; then
        if confirm "  Corregir permisos de todos los archivos marcados [FIX]?"; then
            if ! read_only_mode; then
                chmod 644 /etc/passwd /etc/group 2>/dev/null || true
                chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true
                chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
                chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
                chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null || true
                chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>/dev/null || true
                ok "Permisos de archivos criticos corregidos."
            fi
        fi
    else
        ok "Todos los permisos criticos estan correctos."
    fi
}

# Grupo E: Blacklist de modulos del kernel + USB storage
_os_grupo_modulos() {
    printf '\n%b  ─── GRUPO E: Modulos del kernel (blacklist) ────────────────%b\n' "$C_BLUE" "$C_RESET"
    explain "Estos modulos son raramente necesarios en servidores y representan" \
            "vectores de ataque: filesystems obsoletos y protocolos de red inseguros."

    local -a modulos=(
        "cramfs:Filesystem cramfs (obsoleto)"
        "freevxfs:Filesystem Veritas (sin uso general)"
        "jffs2:Filesystem para flash (no necesario en servidores)"
        "hfs:Filesystem HFS de Apple"
        "hfsplus:Filesystem HFS+ de Apple"
        "udf:Filesystem UDF / DVDs"
        "dccp:Protocolo DCCP (raramente usado)"
        "sctp:Protocolo SCTP (raramente usado)"
    )

    local entry mod desc
    printf '\n'
    for entry in "${modulos[@]}"; do
        mod="${entry%%:*}"; desc="${entry#*:}"
        if lsmod 2>/dev/null | grep -q "^${mod}"; then
            printf '  %b[CARGADO]%b  %-18s %s\n' "$C_RED"   "$C_RESET" "$mod" "$desc"
        else
            printf '  %b[OK     ]%b  %-18s %s\n' "$C_GREEN" "$C_RESET" "$mod" "$desc"
        fi
    done

    local modblk="/etc/modprobe.d/hardening-blacklist.conf"
    if confirm "  Agregar todos a la blacklist de modulos del kernel?"; then
        if ! read_only_mode; then
            local entry2 mod2
            for entry2 in "${modulos[@]}"; do
                mod2="${entry2%%:*}"
                printf 'install %s /bin/true\n' "$mod2"
            done > "$modblk"
            ok "Modulos bloqueados en ${modblk}."
        else
            info "Se crearia blacklist en ${modblk}."
        fi
    fi

    printf '\n'
    explain "Bloquear usb-storage impide montar dispositivos USB. Muy recomendado" \
            "en servidores donde no se necesitan memorias USB."
    if confirm "  Bloquear almacenamiento USB (usb-storage)?"; then
        if ! read_only_mode; then
            echo "install usb-storage /bin/true" >> "$modblk"
            ok "Almacenamiento USB bloqueado."
        else
            info "Se bloquearia usb-storage."
        fi
    fi
}

# ==============================================================================
# PUNTO 5  -  Red: firewall y Suricata  (con politica de acceso)
# ==============================================================================
module_network() {
    title "PUNTO 5 - Red: firewall y deteccion de intrusiones"
    explain "Configuramos el firewall y elegimos la politica de acceso. ANTES de" \
            "cerrar el trafico, garantizamos el acceso SSH para no quedarte fuera."

    if ! command -v ufw >/dev/null 2>&1; then
        if confirm "UFW no esta instalado. Instalarlo ahora?"; then
            run apt-get install -y ufw
        else
            info "Se omite la configuracion del firewall."
            nav_menu "module_dns"
            return 0
        fi
    fi

    if [[ "$AUDIT_ONLY" == true ]]; then
        info "Estado UFW: $(ufw status 2>/dev/null | head -n1)"
        info "Reglas activas:"
        ufw status numbered 2>/dev/null || true
        nav_menu "module_dns"
        return 0
    fi

    # Detectar puerto SSH real (puede haber cambiado en el Punto 1)
    local sshd="/etc/ssh/sshd_config" p
    if [[ -f "$sshd" ]]; then
        p="$(grep -Ei '^\s*Port\s+' "$sshd" | awk '{print $2}' | head -n1)"
        SSH_PORT="${p:-$SSH_PORT}"
    fi
    info "Puerto SSH detectado: ${SSH_PORT}"

    # --- Politica de firewall ---
    printf '\n%b  Politica de firewall:%b\n' "$C_WHITE" "$C_RESET"
    note "  [1]  Segura (recomendada)  — deny-all + SSH garantizado + puertos extra"
    note "  [2]  Whitelist             — solo abro exactamente lo que indico"
    note "  [3]  Blacklist             — bloqueo puertos peligrosos, permito el resto"
    local policy
    read -r -p "$(printf '%b  Seleccion [1/2/3]: %b' "$C_WHITE" "$C_RESET")" policy

    case "$policy" in
        2) _fw_whitelist ;;
        3) _fw_blacklist ;;
        *) _fw_secure    ;;
    esac

    # Suricata IDS
    _fw_suricata

    nav_menu "module_dns"
}

_fw_secure() {
    explain "POLITICA SEGURA: deny-all de entrada. El SSH se permite PRIMERO para" \
            "evitar bloqueos. Opcionalmente se abren puertos adicionales (web, etc.)."
    warn "Politica deny-all de entrada. Puerto SSH a preservar: ${SSH_PORT}"
    if ! confirm "Continuar con la configuracion del firewall?"; then
        info "Firewall cancelado por el usuario."
        return 0
    fi

    run ufw allow "${SSH_PORT}/tcp"
    run ufw limit "${SSH_PORT}/tcp"
    info "Anti-bloqueo: SSH ${SSH_PORT}/tcp permitido y con rate-limit anti fuerza bruta."

    local extra
    read -r -p "$(printf '%b  Puertos extra a permitir (ej. 80,443), vacio para ninguno: %b' "$C_WHITE" "$C_RESET")" extra
    if [[ -n "$extra" ]]; then
        local port
        local -a extra_ports
        IFS=',' read -ra extra_ports <<< "$extra"
        for port in "${extra_ports[@]}"; do
            port="${port// /}"
            [[ "$port" =~ ^[0-9]+$ ]] && run ufw allow "${port}/tcp"
        done
    fi

    run ufw default deny incoming
    run ufw default allow outgoing

    if ! read_only_mode; then
        ufw --force enable >>"$LOG_FILE" 2>&1 || true
        ok "UFW activo: deny-all + SSH ${SSH_PORT} permitido con rate-limit."
    else
        info "Se habilitaria UFW con politica deny-all."
    fi
    warn "Verifica en OTRA terminal que puedes conectar por SSH antes de cerrar esta."
}

_fw_whitelist() {
    explain "WHITELIST: solo permito exactamente los puertos que yo indique." \
            "La opcion mas restrictiva. Ideal para servidores de produccion."
    warn "Se bloqueara TODO el trafico de entrada excepto lo que indiques."
    if ! confirm "Continuar con la configuracion whitelist?"; then return 0; fi

    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${SSH_PORT}/tcp"
    run ufw limit "${SSH_PORT}/tcp"
    info "SSH ${SSH_PORT}/tcp incluido automaticamente (anti-bloqueo)."

    local adding=true
    while [[ "$adding" == true ]]; do
        local port proto
        read -r -p "$(printf '%b  Puerto a permitir (vacio para terminar): %b' "$C_WHITE" "$C_RESET")" port
        [[ -z "$port" ]] && adding=false && break
        read -r -p "$(printf '%b  Protocolo [tcp/udp/both, default tcp]: %b' "$C_WHITE" "$C_RESET")" proto
        proto="${proto:-tcp}"
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            run ufw allow "${port}/${proto}"
            info "Puerto ${port}/${proto} agregado a la whitelist."
        else
            warn "Puerto invalido: ${port}. Ignorado."
        fi
    done

    if ! read_only_mode; then
        ufw --force enable >>"$LOG_FILE" 2>&1 || true
        ok "UFW activo en modo whitelist."
    fi
}

_fw_blacklist() {
    explain "BLACKLIST: permito todo por defecto y bloqueo puertos especificamente" \
            "peligrosos. Util en redes internas con mayor flexibilidad requerida."
    if ! confirm "Continuar con la configuracion blacklist?"; then return 0; fi

    run ufw default allow incoming
    run ufw default allow outgoing

    local -A desc_puerto=(
        [23]="Telnet (inseguro)"       [25]="SMTP (relay abierto)"
        [135]="DCOM RPC"               [137]="NetBIOS Name Service"
        [138]="NetBIOS Datagram"       [139]="NetBIOS Session"
        [445]="SMB/Windows Shares"     [1433]="Microsoft SQL Server"
        [3306]="MySQL (base de datos)" [3389]="RDP (escritorio remoto)"
        [5900]="VNC (escritorio remoto)"
    )

    local p
    for p in 23 25 135 137 138 139 445 1433 3306 3389 5900; do
        if confirm "  Bloquear ${p}/tcp (${desc_puerto[$p]})?"; then
            run ufw deny "${p}/tcp"
        fi
    done

    if ! read_only_mode; then
        ufw --force enable >>"$LOG_FILE" 2>&1 || true
        ok "UFW activo en modo blacklist."
    fi
}

_fw_suricata() {
    if ! pkg_installed suricata; then
        info "Suricata no instalado (Modulo 0 puede instalarlo) para IDS de red."
        return 0
    fi
    if confirm "Configurar Suricata IDS en la interfaz de red principal?"; then
        local iface
        iface="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)"
        info "Interfaz de red detectada: ${iface:-desconocida}"
        if [[ -n "$iface" ]] && ! read_only_mode; then
            sed -i -E "s|^\s*-\s*interface:.*|  - interface: ${iface}|" \
                /etc/suricata/suricata.yaml 2>/dev/null || true
            suricata-update >>"$LOG_FILE" 2>&1 || true
            systemctl enable --now suricata >>"$LOG_FILE" 2>&1 || true
            ok "Suricata configurado en ${iface} y firmas actualizadas."
        else
            info "Se configuraria Suricata en ${iface:-la interfaz detectada}."
        fi
    fi
}

# ==============================================================================
# PUNTO 6  -  DNS seguro  (DoT, DNSSEC, DoH opcional, anti-spoofing)
# ==============================================================================
module_dns() {
    title "PUNTO 6 - DNS seguro"
    explain "El DNS es el directorio de internet: decide a que servidor te conectas." \
            "Sin proteccion, puede ser manipulado para redirigirte a sitios maliciosos." \
            "Configuramos DoT (DNS over TLS), DNSSEC, fallbacks y anti-spoofing."

    if [[ "$AUDIT_ONLY" == true ]]; then
        info "Resolver actual:"
        grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | head -n3 || echo "  (no disponible)"
        if systemctl is-active systemd-resolved >/dev/null 2>&1; then
            info "systemd-resolved: activo"
            resolvectl status 2>/dev/null | grep -E 'DNS (Servers|Over TLS|DNSSEC)' | head -5 || true
        fi
        nav_menu ""
        return 0
    fi

    # --- Elegir servidor DNS ---
    printf '\n%b  Servidor DNS seguro a configurar:%b\n\n' "$C_WHITE" "$C_RESET"
    note "  [1]  Cloudflare          1.1.1.1 / 1.0.0.1          (rapido, privacidad)"
    note "  [2]  Cloudflare+filtro   1.1.1.2 / 1.0.0.2          (bloquea malware)"
    note "  [3]  Quad9               9.9.9.9 / 149.112.112.112   (seguridad + DNSSEC)"
    note "  [4]  Google              8.8.8.8 / 8.8.4.4           (confiable, universal)"
    note "  [5]  Personalizado"
    note "  [0]  Omitir este punto"
    local dns_choice dns1 dns2
    read -r -p "$(printf '%b  Seleccion [0-5]: %b' "$C_WHITE" "$C_RESET")" dns_choice
    case "$dns_choice" in
        1) dns1="1.1.1.1";  dns2="1.0.0.1" ;;
        2) dns1="1.1.1.2";  dns2="1.0.0.2" ;;
        3) dns1="9.9.9.9";  dns2="149.112.112.112" ;;
        4) dns1="8.8.8.8";  dns2="8.8.4.4" ;;
        5)
            read -r -p "  DNS primario  : " dns1
            read -r -p "  DNS secundario: " dns2
            ;;
        *)
            info "Se omite la configuracion de DNS."
            nav_menu ""
            return 0
            ;;
    esac

    # --- Configurar segun el sistema de resolucion disponible ---
    if systemctl list-unit-files 2>/dev/null | grep -q systemd-resolved; then
        _dns_systemd_resolved "$dns1" "$dns2"
    else
        _dns_resolv_conf "$dns1" "$dns2"
    fi

    # --- DNS over HTTPS con dnscrypt-proxy (opcional) ---
    _dns_doh_offer

    # --- Anti-spoofing via auditd ---
    _dns_antispoofing

    nav_menu ""
}

_dns_systemd_resolved() {
    local dns1="$1" dns2="$2"
    local rconf="/etc/systemd/resolved.conf"
    explain "systemd-resolved gestiona el DNS del sistema. Activamos DNS over TLS" \
            "(cifra las consultas en transito) y DNSSEC (valida la autenticidad de" \
            "las respuestas). Tambien desactivamos mDNS y LLMNR (menor superficie)."
    backup_file "$rconf"
    if ! read_only_mode; then
        set_config_kv "$rconf" "DNS=" "${dns1} ${dns2}"
        set_config_kv "$rconf" "FallbackDNS=" "9.9.9.9 149.112.112.112"
        set_config_kv "$rconf" "DNSOverTLS=" "yes"
        set_config_kv "$rconf" "DNSSEC=" "yes"
        set_config_kv "$rconf" "MulticastDNS=" "no"
        set_config_kv "$rconf" "LLMNR=" "no"
        systemctl restart systemd-resolved >>"$LOG_FILE" 2>&1 || true
        ok "DNS ${dns1}/${dns2} configurado con DoT y DNSSEC activados."
        ok "mDNS y LLMNR deshabilitados (reducen superficie de ataque)."
    else
        info "Se configuraria DNS ${dns1}/${dns2} con DoT y DNSSEC en systemd-resolved."
    fi
}

_dns_resolv_conf() {
    local dns1="$1" dns2="$2"
    explain "Sin systemd-resolved, escribimos /etc/resolv.conf directamente y lo" \
            "protegemos con el atributo inmutable (chattr +i) para evitar que" \
            "NetworkManager u otros servicios lo sobreescriban."
    if ! read_only_mode; then
        backup_file "/etc/resolv.conf"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        printf 'nameserver %s\nnameserver %s\n' "$dns1" "$dns2" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null \
            && ok "resolv.conf protegido (inmutable) contra sobreescritura." || true
        ok "DNS ${dns1}/${dns2} configurado en resolv.conf."
    else
        info "Se escribiria ${dns1}/${dns2} en resolv.conf (inmutable)."
    fi
}

_dns_doh_offer() {
    printf '\n'
    explain "dnscrypt-proxy añade DNS over HTTPS (DoH): cifra el trafico DNS usando" \
            "HTTPS, lo que hace mucho mas dificil que tu ISP o un atacante intercepte" \
            "o manipule las consultas DNS. Capa adicional sobre DoT."
    if pkg_installed dnscrypt-proxy; then
        ok "dnscrypt-proxy ya esta instalado."
        local state
        state="$(systemctl is-active dnscrypt-proxy 2>/dev/null || echo 'inactivo')"
        info "Estado: ${state}"
        if confirm "Reiniciar dnscrypt-proxy?"; then
            run systemctl restart dnscrypt-proxy 2>/dev/null || true
        fi
    elif confirm "Instalar dnscrypt-proxy (DNS over HTTPS, capa adicional de privacidad)?"; then
        if ! read_only_mode; then
            apt-get install -y dnscrypt-proxy >>"$LOG_FILE" 2>&1 || true
            systemctl enable --now dnscrypt-proxy 2>>"$LOG_FILE" || true
            ok "dnscrypt-proxy instalado y activo."
        else
            info "Se instalaria dnscrypt-proxy."
        fi
    fi
}

_dns_antispoofing() {
    printf '\n'
    if pkg_installed auditd; then
        local dnsrules="/etc/audit/rules.d/dns.rules"
        if ! read_only_mode; then
            cat >"$dnsrules" <<'EOF'
## Anti-spoofing: monitoreo de archivos DNS criticos
-w /etc/hosts -p wa -k dns
-w /etc/resolv.conf -p wa -k dns
EOF
            augenrules --load 2>>"$LOG_FILE" || true
            ok "Monitoreo auditd activado: /etc/hosts y /etc/resolv.conf (anti-spoofing)."
        else
            info "Se activaria monitoreo auditd de archivos DNS."
        fi
    fi
}

# ==============================================================================
# Menu principal y orquestacion
# ==============================================================================
apply_all() {
    APPLY_ALL=true
    module_prereqs
    module_ssh
    module_logging
    module_patches
    module_os
    module_network
    module_dns
    APPLY_ALL=false
    title "Hardening completo"
    ok "Todos los modulos ejecutados. Log: ${LOG_FILE}"
    [[ "$DRY_RUN" == false && "$AUDIT_ONLY" == false ]] && ok "Backups en: ${BACKUP_DIR}"
    [[ "$DRY_RUN" == false && "$AUDIT_ONLY" == false ]] && ok "Reporte en: ${REPORT_FILE}"
}

show_menu() {
    local sep="══════════════════════════════════════════════════════════════"
    printf '\n'
    printf '%b  %s%b\n'  "$C_BLUE" "$sep" "$C_RESET"
    printf '%b  %-62s%b\n' "$C_BLUE" \
        "   HARDENING TOOLKIT  v${SCRIPT_VERSION}   |   ${DISTRO_NAME}" "$C_RESET"
    printf '%b  %s%b\n'  "$C_BLUE" "$sep" "$C_RESET"
    if [[ "$DRY_RUN"    == true ]]; then
        printf '  %b◆ MODO SIMULACION — ningun cambio se aplica%b\n' "$C_CYAN" "$C_RESET"
    fi
    if [[ "$AUDIT_ONLY" == true ]]; then
        printf '  %b◆ MODO AUDITORIA  — solo lectura%b\n' "$C_CYAN" "$C_RESET"
    fi
    printf '\n'
    printf '  %b0 »%b  Prerrequisitos      Instalar y verificar herramientas base\n'   "$C_WHITE" "$C_RESET"
    printf '  %b1 »%b  SSH                 Hardening del acceso remoto\n'               "$C_WHITE" "$C_RESET"
    printf '  %b2 »%b  Logging & SIEM      Auditoria, logs y centralizacion\n'          "$C_WHITE" "$C_RESET"
    printf '  %b3 »%b  Parches             Actualizaciones, CVEs y reporte\n'           "$C_WHITE" "$C_RESET"
    printf '  %b4 »%b  Sistema operativo   Kernel, servicios y permisos\n'              "$C_WHITE" "$C_RESET"
    printf '  %b5 »%b  Red & Firewall      UFW, politica de acceso y Suricata\n'        "$C_WHITE" "$C_RESET"
    printf '  %b6 »%b  DNS seguro          DoT, DNSSEC, DoH y anti-spoofing\n'          "$C_WHITE" "$C_RESET"
    printf '\n'
    printf '%b  %s%b\n'  "$C_BLUE" "$sep" "$C_RESET"
    printf '  %bT »%b  Aplicar TODO                   %bQ »%b  Salir\n' \
        "$C_WHITE" "$C_RESET" "$C_WHITE" "$C_RESET"
    printf '%b  %s%b\n'  "$C_BLUE" "$sep" "$C_RESET"
    printf '\n'
}

main_menu() {
    local opt
    while true; do
        show_menu
        read -r -p "$(printf '%b  Seleccion: %b' "$C_WHITE" "$C_RESET")" opt
        case "${opt^^}" in
            0) module_prereqs  ;;
            1) module_ssh      ;;
            2) module_logging  ;;
            3) module_patches  ;;
            4) module_os       ;;
            5) module_network  ;;
            6) module_dns      ;;
            T) apply_all       ;;
            Q) info "Saliendo. Log: ${LOG_FILE}"; break ;;
            *) warn "Opcion no valida. Usa 0-6, T o Q." ;;
        esac
    done
}

usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — Ubuntu/Debian Endpoint Hardening Toolkit

Uso: sudo ./${SCRIPT_NAME} [opciones]

Opciones:
  --dry-run    Muestra lo que haria cada modulo SIN aplicar cambios.
  --audit      Solo reporta el estado actual del sistema (solo lectura).
  --yes        Responde 'si' a las confirmaciones (uso no interactivo, con cuidado).
  -h, --help   Muestra esta ayuda.

Sin opciones: abre el menu interactivo.

Recomendaciones:
  * Ejecutar primero con --audit para ver el estado, luego --dry-run para simular.
  * Probar siempre en una VM con snapshot antes de produccion.
  * Al endurecer SSH/firewall, mantener una sesion abierta y verificar el
    acceso en una segunda terminal antes de cerrar la actual.
EOF
}

# ------------------------------------------------------------------------------
# Parseo de argumentos
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=true ;;
            --audit)   AUDIT_ONLY=true ;;
            --yes)     ASSUME_YES=true ;;
            -h|--help) usage; exit 0 ;;
            *) err "Opcion desconocida: $1"; usage; exit 1 ;;
        esac
        shift
    done
}

# ------------------------------------------------------------------------------
# Punto de entrada
# ------------------------------------------------------------------------------
main() {
    parse_args "$@"
    require_root
    detect_distro
    ensure_backup_dir
    log "Inicio ${SCRIPT_NAME} v${SCRIPT_VERSION} (dry-run=${DRY_RUN}, audit=${AUDIT_ONLY})"

    title "${SCRIPT_NAME} v${SCRIPT_VERSION}"
    info "Sistema detectado: ${DISTRO_NAME} ${DISTRO_VERSION}"
    if [[ "$DRY_RUN" == false && "$AUDIT_ONLY" == false ]]; then
        warn "Vas a modificar la configuracion del sistema. Se crearan backups en ${BACKUP_DIR}."
        warn "Recomendado: ejecutar primero con --audit y luego --dry-run."
    fi
    main_menu
}

# Permite hacer "source" del script desde tests (bats) sin ejecutar main().
# Cuando se ejecuta directamente (./hardening_ubuntu.sh), BASH_SOURCE[0] == $0.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
