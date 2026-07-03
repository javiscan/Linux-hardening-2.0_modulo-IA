# Integración con Wazuh (SIEM)

Conecta la telemetría de esta plataforma con Wazuh, junto con Suricata (NIDS) y
auditd (HIDS). Explicación completa en `../../docs/IA_Y_WAZUH_SIEM.md`.

## Pasos rápidos

1. **Manager** (servidor central):
   ```bash
   curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a
   ```
2. **Agente** en cada endpoint:
   ```bash
   WAZUH_MANAGER='IP_DEL_MANAGER' apt-get install wazuh-agent -y
   systemctl enable --now wazuh-agent
   ```
3. **Telemetría** (agente): copiá los bloques de `ossec-hardening.xml` dentro de
   `/var/ossec/etc/ossec.conf` y reiniciá: `systemctl restart wazuh-agent`.
4. **Reglas propias** (opcional, manager): agregá `rules-hardening.xml` a
   `/var/ossec/etc/rules/local_rules.xml` y reiniciá: `systemctl restart wazuh-manager`.

## Verificar que Wazuh lee Suricata
```bash
# Desde otra máquina autorizada: generá tráfico que Suricata detecte
nmap -sS -p 1-1000 IP_DEL_ENDPOINT
# En el endpoint: Suricata lo registra
tail -f /var/log/suricata/eve.json | grep alert
# En el manager: la alerta llega a Wazuh
tail -f /var/ossec/logs/alerts/alerts.json | grep -i suricata
# Estado del agente
/var/ossec/bin/agent_control -l
```

> Nota: los archivos .xml son PLANTILLAS. Ajustá rutas/IP a tu entorno y probá en
> una VM antes de producción.
