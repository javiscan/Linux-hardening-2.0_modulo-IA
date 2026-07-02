#!/usr/bin/env bash
# Modulo OS: parametros de kernel (sysctl) segun CIS.
MODULE_ID="os"; MODULE_VERSION="2.0.0"; MODULE_SEVERITY="medium"; MODULE_CIS="3.x"
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"

module_describe() { echo "sysctl CIS: ASLR, SYN cookies, anti-spoofing, etc."; }

module_audit() {
    local aslr fwd; aslr="$(sysctl -n kernel.randomize_va_space 2>/dev/null)"; fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    [[ "$aslr" == "2" ]] && report_event "$MODULE_ID" "aslr" "pass" "medium" "ASLR=2" \
        || report_event "$MODULE_ID" "aslr" "fail" "medium" "kernel.randomize_va_space=${aslr:-?}"
    [[ "$fwd" == "0" ]] && report_event "$MODULE_ID" "ip_forward" "pass" "low" "ip_forward=0" \
        || report_event "$MODULE_ID" "ip_forward" "fail" "low" "net.ipv4.ip_forward=${fwd:-?}"
}

module_apply() {
    if ! state_is_version "${MODULE_ID}:sysctl" "$MODULE_VERSION"; then
        if ! core_read_only; then
            cat >"$SYSCTL_FILE" <<'SYS'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYS
            sysctl --system >/dev/null 2>&1 || true
        else
            info "Se escribirian parametros sysctl CIS en ${SYSCTL_FILE}"
        fi
        state_mark_applied "${MODULE_ID}:sysctl" "$MODULE_VERSION"
        report_event "$MODULE_ID" "sysctl_cis" "applied" "medium" "parametros sysctl CIS aplicados"
    else
        report_event "$MODULE_ID" "sysctl_cis" "skipped" "medium" "ya aplicado"
    fi
}
