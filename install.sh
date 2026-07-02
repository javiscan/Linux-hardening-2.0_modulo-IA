#!/usr/bin/env bash
# install.sh - prepara el entorno (git clone + ./install.sh).
set -o pipefail
[[ "${EUID}" -ne 0 ]] && { echo "Ejecutar como root: sudo ./install.sh"; exit 1; }
echo "[*] Creando estado en /var/lib/hardening ..."
mkdir -p /var/lib/hardening && chmod 700 /var/lib/hardening
chmod +x hardening_2.0+IA.sh modules/*.sh lib/*.sh 2>/dev/null || true
[[ -f config/platform.conf ]] || cp config/platform.conf.example config/platform.conf 2>/dev/null || true
echo "[*] Listo. Proximos pasos:"
echo "    sudo ./hardening_2.0+IA.sh --audit      # ver estado"
echo "    sudo ./hardening_2.0+IA.sh --dry-run    # simular"
echo "    sudo ./hardening_2.0+IA.sh --apply --profile server"
