#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
timestamp=$(date -u +%Y%m%dT%H%M%SZ)

die() { echo "ERROR: $*" >&2; exit 1; }
note() { printf '\n== %s ==\n' "$*"; }
require_root() { [ "$(id -u)" -eq 0 ] || die "run this installer as root"; }
require_file() { [ -f "$1" ] || die "required file not found: $1"; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

ask() {
    prompt=$1 default=${2-}
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default" >&2
    else
        printf '%s: ' "$prompt" >&2
    fi
    IFS= read -r answer
    printf '%s\n' "${answer:-$default}"
}

ask_secret() {
    prompt=$1
    printf '%s: ' "$prompt" >&2
    stty -echo
    IFS= read -r answer
    stty echo
    printf '\n' >&2
    printf '%s\n' "$answer"
}

confirm() {
    prompt=$1 default=${2:-no}
    if [ "$default" = yes ]; then suffix='[Y/n]'; else suffix='[y/N]'; fi
    printf '%s %s ' "$prompt" "$suffix" >&2
    IFS= read -r answer
    case "${answer:-$default}" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

safe_value() {
    value=$1 label=$2
    case "$value" in *"'"*|*'"'*) die "$label must not contain quote characters" ;; esac
    [ -n "$value" ] || die "$label must not be empty"
}

safe_path() {
    value=$1 label=$2
    safe_value "$value" "$label"
    case "$value" in *[!A-Za-z0-9_./-]*) die "$label contains unsupported characters" ;; esac
}

backup_file() {
    target=$1 rollback=$2
    if [ -e "$target" ] || [ -L "$target" ]; then
        destination="$rollback$target"
        install -d -m 0700 "$(dirname "$destination")"
        cp -a "$target" "$destination"
    fi
}

validate_certificate_key() {
    certificate=$1 key=$2 label=$3
    require_file "$certificate"
    require_file "$key"
    cert_hash=$(openssl x509 -in "$certificate" -pubkey -noout | sha256sum | cut -d' ' -f1)
    key_hash=$(openssl pkey -in "$key" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
    [ "$cert_hash" = "$key_hash" ] || die "$label certificate and key do not match"
}

install_login01() {
    require_root
    for command in install systemctl openssl python3 sha256sum; do require_command "$command"; done
    note "LOGIN01 guided installation"

    binary=$(ask "Path to sw-badge-server Linux binary" "$project_dir/bin/sw-badge-server")
    tls_cert=$(ask "Path to LOGIN01 TLS certificate")
    tls_key=$(ask "Path to LOGIN01 TLS private key")
    pkinit_cert=$(ask "Path to PKINIT CA certificate")
    pkinit_key=$(ask "Path to PKINIT CA private key")
    listen=$(ask "HTTPS listen address" "0.0.0.0:8080")
    directory_url=$(ask "Domain controller LDAPS URL" "ldaps://dc01.example.test:636")
    base_dn=$(ask "Active Directory base DN" "DC=example,DC=test")
    bind_dn=$(ask "SWBA LDAP service account UPN")
    domain=$(ask "Active Directory DNS domain" "example.test")
    admin_group=$(ask "SWBA administrator group DN" "CN=SWBadge-Admins,CN=Users,$base_dn")
    realm=$(ask "Kerberos realm" "$(printf '%s' "$domain" | tr '[:lower:]' '[:upper:]')")
    client_target_version=$(ask "Managed Linux client target version" "1.2.1")
    directory_cert_sha256=$(ask "DC LDAPS certificate SHA-256 pin (optional)")
    bind_password=$(ask_secret "LDAP service account password (not displayed)")

    for item in "$binary" "$tls_cert" "$tls_key" "$pkinit_cert" "$pkinit_key"; do require_file "$item"; done
    for pair in "$listen|listen address" "$directory_url|directory URL" "$base_dn|base DN" "$bind_dn|bind DN" "$domain|domain" "$admin_group|admin group" "$realm|realm" "$client_target_version|client target version"; do
        safe_value "${pair%%|*}" "${pair#*|}"
    done
    [ -n "$bind_password" ] || die "LDAP password must not be empty"
    case "$directory_url" in ldaps://*) ;; *) die "directory URL must use ldaps://" ;; esac
    if [ -n "$directory_cert_sha256" ]; then
        case "$directory_cert_sha256" in *[!A-Fa-f0-9:]*) die "invalid LDAPS certificate fingerprint" ;; esac
    fi
    validate_certificate_key "$tls_cert" "$tls_key" "TLS"
    validate_certificate_key "$pkinit_cert" "$pkinit_key" "PKINIT CA"
    openssl x509 -in "$tls_cert" -noout -checkend 2592000 >/dev/null || die "TLS certificate expires within 30 days"
    openssl x509 -in "$pkinit_cert" -noout -checkend 2592000 >/dev/null || die "PKINIT CA expires within 30 days"

    echo "Binary: $binary ($("$binary" -version 2>/dev/null || echo unknown-version))"
    echo "Directory: $directory_url / $base_dn"
    echo "Realm: $realm"
    echo "Secrets will be installed root-readable and will not be printed."
    confirm "Install LOGIN01 now?" || die "cancelled"

    rollback="/root/swbadge-login01-install-rollback-$timestamp"
    install -d -m 0700 "$rollback"
    for target in /opt/stumpfworks-badge/sw-badge-server /etc/stumpfworks-badge/config.yaml /etc/stumpfworks-badge/ldap-password /etc/stumpfworks-badge/session-secret /etc/systemd/system/sw-badge-server.service /etc/systemd/system/swbadge-login01-maintenance.service /etc/systemd/system/swbadge-login01-maintenance.timer /usr/local/sbin/swbadge-cert-check /usr/local/sbin/swbadge-sqlite-backup /usr/local/sbin/swbadge-postgres-backup; do
        backup_file "$target" "$rollback"
    done

    id swbadge >/dev/null 2>&1 || useradd --system --home /var/lib/stumpfworks-badge --shell /usr/sbin/nologin swbadge
    install -d -o root -g root -m 0755 /opt/stumpfworks-badge
    install -d -o swbadge -g swbadge -m 0750 /var/lib/stumpfworks-badge /var/log/stumpfworks-badge
    install -d -o root -g swbadge -m 0750 /etc/stumpfworks-badge
    install -d -o root -g swbadge -m 0750 /etc/stumpfworks-badge/tls /etc/stumpfworks-badge/pkinit-ca
    install -o root -g root -m 0755 "$binary" /opt/stumpfworks-badge/sw-badge-server
    install -o root -g swbadge -m 0640 "$tls_cert" /etc/stumpfworks-badge/tls/server.crt
    install -o root -g swbadge -m 0640 "$tls_key" /etc/stumpfworks-badge/tls/server.key
    install -o root -g swbadge -m 0640 "$pkinit_cert" /etc/stumpfworks-badge/pkinit-ca/ca.crt
    install -o root -g swbadge -m 0640 "$pkinit_key" /etc/stumpfworks-badge/pkinit-ca/ca.key
    umask 077
    secret_tmp=$(mktemp)
    trap 'rm -f "$secret_tmp"' EXIT INT TERM
    printf '%s' "$bind_password" > "$secret_tmp"
    install -o root -g swbadge -m 0640 "$secret_tmp" /etc/stumpfworks-badge/ldap-password
    openssl rand -base64 48 > "$secret_tmp"
    install -o root -g swbadge -m 0640 "$secret_tmp" /etc/stumpfworks-badge/session-secret
    rm -f "$secret_tmp"
    trap - EXIT INT TERM

    cat > /etc/stumpfworks-badge/config.yaml <<EOF
server:
  listen: "$listen"
  tls_cert_file: "/etc/stumpfworks-badge/tls/server.crt"
  tls_key_file: "/etc/stumpfworks-badge/tls/server.key"
database:
  path: "/var/lib/stumpfworks-badge/badges.db"
directory:
  enabled: true
  url: "$directory_url"
  base_dn: "$base_dn"
  bind_dn: "$bind_dn"
  bind_password_file: "/etc/stumpfworks-badge/ldap-password"
  domain: "$domain"
  admin_group_dn: "$admin_group"
  cert_sha256: "$directory_cert_sha256"
auth:
  session_secret_file: "/etc/stumpfworks-badge/session-secret"
pkinit:
  enabled: true
  ca_cert_file: "/etc/stumpfworks-badge/pkinit-ca/ca.crt"
  ca_key_file: "/etc/stumpfworks-badge/pkinit-ca/ca.key"
  realm: "$realm"
updates:
  client_target_version: "$client_target_version"
EOF
    chown root:swbadge /etc/stumpfworks-badge/config.yaml
    chmod 0640 /etc/stumpfworks-badge/config.yaml

    install -o root -g root -m 0644 "$project_dir/deploy/systemd/sw-badge-server.service" /etc/systemd/system/sw-badge-server.service
    install -o root -g root -m 0755 "$project_dir/scripts/swbadge-cert-check.sh" /usr/local/sbin/swbadge-cert-check
    install -o root -g root -m 0755 "$project_dir/scripts/swbadge-sqlite-backup.py" /usr/local/sbin/swbadge-sqlite-backup
    install -o root -g root -m 0755 "$project_dir/scripts/swbadge-postgres-backup.py" /usr/local/sbin/swbadge-postgres-backup
    install -o root -g root -m 0644 "$project_dir/deploy/systemd/swbadge-login01-maintenance.service" /etc/systemd/system/swbadge-login01-maintenance.service
    install -o root -g root -m 0644 "$project_dir/deploy/systemd/swbadge-login01-maintenance.timer" /etc/systemd/system/swbadge-login01-maintenance.timer
    install -d -o root -g root -m 0700 /var/backups/stumpfworks-badge
    systemctl daemon-reload
    systemctl enable sw-badge-server.service swbadge-login01-maintenance.timer

    if confirm "Start/restart SWBA and run maintenance checks now?" yes; then
        systemctl restart sw-badge-server.service
        systemctl start swbadge-login01-maintenance.service
        systemctl start swbadge-login01-maintenance.timer
        systemctl --no-pager --full status sw-badge-server.service
    fi
    echo "LOGIN01 installation completed. Rollback files: $rollback"
}

install_client() {
    require_root
    for command in install systemctl python3 awk grep find; do require_command "$command"; done
    note "Linux client guided installation"

    pam_binary=$(ask "Path to sw-badge-pam-helper Linux binary" "$project_dir/bin/sw-badge-pam-helper")
    status_binary=$(ask "Path to sw-badge-client-status Linux binary" "$project_dir/bin/sw-badge-client-status")
    diagnostics_binary=$(ask "Path to sw-badge-client-diagnostics Linux binary" "$project_dir/bin/sw-badge-client-diagnostics")
    updater_binary=$(ask "Path to sw-badge-client-updater Linux binary" "$project_dir/bin/sw-badge-client-updater")
    update_public_key=$(ask "Path to trusted client-update public key")
    ca_source=$(ask "Path to trusted Homelab CA certificate")
    server_url=$(ask "LOGIN01 HTTPS URL" "https://login01.example.test:8080")
    client_id=$(ask "Unique client ID" "$(hostname -s)-greeter")
    realm=$(ask "Kerberos realm" "EXAMPLE.TEST")
    camera_resolution=$(ask "Camera scan resolution" "640x480")
    file01_mounts=$(ask "Install FILE01 Kerberos mounts (yes/no)" "yes")
    client_status_token=$(ask_secret "Provisioned LOGIN01 client-status token (not displayed)")
    require_file "$pam_binary"
    require_file "$status_binary"
    require_file "$diagnostics_binary"
    require_file "$updater_binary"
    require_file "$update_public_key"
    require_file "$ca_source"
    case "$server_url" in https://*) ;; *) die "server URL must use https://" ;; esac
    for pair in "$server_url|server URL" "$client_id|client ID" "$realm|realm"; do safe_value "${pair%%|*}" "${pair#*|}"; done
    case "$camera_resolution" in *[!0-9x]*|*x*x*|x*|*x) die "camera resolution must look like 640x480" ;; esac
    case "$file01_mounts" in yes|no) ;; *) die "FILE01 mount selection must be yes or no" ;; esac
    [ -n "$client_status_token" ] || die "client-status token must not be empty"
    for command in lightdm zbarcam kinit getent nmcli; do require_command "$command"; done
    find /usr/lib -path '*/krb5/plugins/preauth/pkinit.so' -print -quit | grep -q . || die "Kerberos PKINIT plugin is missing; install krb5-pkinit"
    if [ "$file01_mounts" = yes ]; then
        require_command mount.cifs
        require_file "$project_dir/deploy/client/pam_mount.conf.xml"
        grep -q 'pam_mount.so' /etc/pam.d/common-auth || die "pam_mount is not enabled; install libpam-mount first"
        grep -q 'pam_mount.so' /etc/pam.d/common-session || die "pam_mount session handling is not enabled"
    fi
    python3 -c 'import gi; gi.require_version("Gtk","3.0"); gi.require_version("LightDM","1")' || die "GTK3/LightDM Python bindings are missing"
    openssl x509 -in "$ca_source" -noout -checkend 2592000 >/dev/null || die "Homelab CA expires within 30 days"

    echo "Server: $server_url"
    echo "Client: $client_id"
    echo "Realm: $realm"
    echo "The existing PAM and LightDM configuration will be backed up."
    confirm "Install the native SWBA client now?" || die "cancelled"

    rollback="/root/swbadge-client-install-rollback-$timestamp"
    install -d -m 0700 "$rollback"
    for target in /etc/pam.d/lightdm /etc/lightdm/lightdm.conf.d/60-stumpfworks-badge.conf /usr/share/xgreeters/sw-badge-greeter.desktop /usr/local/bin/sw-badge-native-greeter /usr/local/bin/sw-badge-native-greeter-wrapper /usr/local/bin/sw-badge-camera-linux /usr/local/libexec/sw-badge-pam-helper /usr/local/libexec/sw-badge-pam-helper-wrapper /usr/local/libexec/sw-badge-client-status /usr/local/sbin/sw-badge-client-diagnostics /usr/local/sbin/sw-badge-client-updater /etc/stumpfworks-badge/client-update.pub /etc/stumpfworks-badge/client.conf /etc/stumpfworks-badge/client-status-token /etc/systemd/system/swbadge-client-status.service /etc/systemd/system/swbadge-client-status.timer /etc/polkit-1/rules.d/49-swbadge-networkmanager.rules /etc/security/pam_mount.conf.xml; do
        backup_file "$target" "$rollback"
    done

    install -d -o root -g root -m 0755 /usr/local/libexec /usr/local/bin
    install -d -o root -g lightdm -m 0750 /etc/stumpfworks-badge
    install -o root -g root -m 0755 "$pam_binary" /usr/local/libexec/sw-badge-pam-helper
    install -o root -g root -m 0755 "$status_binary" /usr/local/libexec/sw-badge-client-status
    install -o root -g root -m 0755 "$diagnostics_binary" /usr/local/sbin/sw-badge-client-diagnostics
    install -o root -g root -m 0755 "$updater_binary" /usr/local/sbin/sw-badge-client-updater
    install -o root -g root -m 0644 "$update_public_key" /etc/stumpfworks-badge/client-update.pub
    install -o root -g root -m 0755 "$project_dir/scripts/sw-badge-pam-helper-wrapper.sh" /usr/local/libexec/sw-badge-pam-helper-wrapper
    install -o root -g root -m 0755 "$project_dir/cmd/native-greeter/sw-badge-native-greeter.py" /usr/local/bin/sw-badge-native-greeter
    # A project copied from Windows may have CRLF line endings. Normalize the
    # executable so its /usr/bin/python3 shebang remains valid on Linux.
    sed -i 's/\r$//' /usr/local/bin/sw-badge-native-greeter
    install -o root -g root -m 0755 "$project_dir/scripts/sw-badge-native-greeter-wrapper.sh" /usr/local/bin/sw-badge-native-greeter-wrapper
    install -o root -g root -m 0755 "$project_dir/scripts/sw-badge-camera-linux.sh" /usr/local/bin/sw-badge-camera-linux
    install -o root -g root -m 0644 "$project_dir/deploy/polkit/49-swbadge-networkmanager.rules" /etc/polkit-1/rules.d/49-swbadge-networkmanager.rules
    if [ "$file01_mounts" = yes ]; then
        install -o root -g root -m 0644 "$project_dir/deploy/client/pam_mount.conf.xml" /etc/security/pam_mount.conf.xml
    fi
    install -o root -g lightdm -m 0640 "$ca_source" /etc/stumpfworks-badge/stumpfworks-homelab-ca.crt
    cat > /etc/stumpfworks-badge/client.conf <<EOF
SWBADGE_SERVER='$server_url'
SWBADGE_CLIENT_ID='$client_id'
SWBADGE_CA_FILE='/etc/stumpfworks-badge/stumpfworks-homelab-ca.crt'
SWBADGE_CAMERA_HELPER='/usr/local/bin/sw-badge-camera-linux'
SWBADGE_CAMERA_RESOLUTION='$camera_resolution'
SWBADGE_GRANT_FILE='/run/swbadge/login-grant'
SWBADGE_REALM='$realm'
SWBADGE_CLIENT_TOKEN_FILE='/etc/stumpfworks-badge/client-status-token'
SWBADGE_UPDATE_PUBLIC_KEY='/etc/stumpfworks-badge/client-update.pub'
EOF
    chown root:lightdm /etc/stumpfworks-badge/client.conf
    chmod 0640 /etc/stumpfworks-badge/client.conf
    umask 077
    token_tmp=$(mktemp)
    trap 'rm -f "$token_tmp"' EXIT INT TERM
    printf '%s' "$client_status_token" > "$token_tmp"
    install -o root -g root -m 0600 "$token_tmp" /etc/stumpfworks-badge/client-status-token
    rm -f "$token_tmp"
    trap - EXIT INT TERM
    install -o root -g root -m 0644 "$project_dir/deploy/lightdm/sw-badge-greeter.desktop" /usr/share/xgreeters/sw-badge-greeter.desktop
    install -d -o root -g root -m 0755 /etc/lightdm/lightdm.conf.d
    install -o root -g root -m 0644 "$project_dir/deploy/lightdm/60-stumpfworks-native-greeter.conf" /etc/lightdm/lightdm.conf.d/60-stumpfworks-badge.conf
    install -o root -g root -m 0644 "$project_dir/deploy/tmpfiles/swbadge.conf" /usr/lib/tmpfiles.d/swbadge.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/swbadge.conf
    install -o root -g root -m 0644 "$project_dir/deploy/systemd/swbadge-client-status.service" /etc/systemd/system/swbadge-client-status.service
    install -o root -g root -m 0644 "$project_dir/deploy/systemd/swbadge-client-status.timer" /etc/systemd/system/swbadge-client-status.timer
    systemctl daemon-reload
    systemctl enable swbadge-client-status.timer

    pam_rule='auth [success=done default=ignore] pam_exec.so quiet quiet_log /usr/local/libexec/sw-badge-pam-helper-wrapper'
    if ! grep -Fq 'sw-badge-pam-helper-wrapper' /etc/pam.d/lightdm; then
        awk -v rule="$pam_rule" 'BEGIN{done=0} !done && /^@include[[:space:]]+common-auth/{print rule; done=1} {print} END{if(!done) exit 42}' /etc/pam.d/lightdm > /etc/pam.d/lightdm.swbadge-new || die "common-auth include not found; PAM file unchanged"
        chown root:root /etc/pam.d/lightdm.swbadge-new
        chmod 0644 /etc/pam.d/lightdm.swbadge-new
        mv /etc/pam.d/lightdm.swbadge-new /etc/pam.d/lightdm
    fi

    python3 -m py_compile /usr/local/bin/sw-badge-native-greeter
    /usr/local/sbin/sw-badge-client-updater --version
    nmcli general status >/dev/null
    systemctl start swbadge-client-status.service
    install -d -o root -g root -m 0700 /var/lib/stumpfworks-badge/diagnostics
    set -a
    . /etc/stumpfworks-badge/client.conf
    set +a
    /usr/local/sbin/sw-badge-client-diagnostics --output "/var/lib/stumpfworks-badge/diagnostics/install-$timestamp.zip"
    if confirm "Restart LightDM now? This ends the current graphical session."; then
        systemctl restart lightdm
        systemctl --no-pager --full status lightdm
    fi
    echo "Client installation completed. Rollback files: $rollback"
}

install_dc_monitoring() {
    require_root
    for command in install systemctl openssl; do require_command "$command"; done
    note "DC01 certificate monitoring"
    kdc_cert=$(ask "Path to installed KDC certificate" "/var/lib/samba/private/pkinit/dc01-kdc.crt")
    ca_cert=$(ask "Path to installed PKINIT CA certificate" "/var/lib/samba/private/pkinit/pkinit-ca.crt")
    require_file "$kdc_cert"
    require_file "$ca_cert"
    safe_path "$kdc_cert" "KDC certificate path"
    safe_path "$ca_cert" "PKINIT CA certificate path"
    openssl x509 -in "$kdc_cert" -noout -checkend 2592000 >/dev/null || die "KDC certificate expires within 30 days"
    openssl x509 -in "$ca_cert" -noout -checkend 2592000 >/dev/null || die "PKINIT CA expires within 30 days"
    echo "This role installs monitoring only; it never rewrites Samba or Kerberos configuration."
    confirm "Type yes to confirm that a current DC backup exists and install monitoring?" || die "cancelled"

    rollback="/root/swbadge-dc-monitoring-rollback-$timestamp"
    install -d -m 0700 "$rollback"
    for target in /usr/local/sbin/swbadge-cert-check /etc/systemd/system/swbadge-dc01-cert-check.service /etc/systemd/system/swbadge-dc01-cert-check.timer; do backup_file "$target" "$rollback"; done
    install -o root -g root -m 0755 "$project_dir/scripts/swbadge-cert-check.sh" /usr/local/sbin/swbadge-cert-check
    sed "s|/var/lib/samba/private/pkinit/dc01-kdc.crt|$kdc_cert|; s|/var/lib/samba/private/pkinit/pkinit-ca.crt|$ca_cert|" "$project_dir/deploy/systemd/swbadge-dc01-cert-check.service" > /etc/systemd/system/swbadge-dc01-cert-check.service
    chown root:root /etc/systemd/system/swbadge-dc01-cert-check.service
    chmod 0644 /etc/systemd/system/swbadge-dc01-cert-check.service
    install -o root -g root -m 0644 "$project_dir/deploy/systemd/swbadge-dc01-cert-check.timer" /etc/systemd/system/swbadge-dc01-cert-check.timer
    systemctl daemon-reload
    systemctl start swbadge-dc01-cert-check.service
    systemctl enable --now swbadge-dc01-cert-check.timer
    systemctl show swbadge-dc01-cert-check.service -p Result -p ExecMainStatus
    echo "DC01 monitoring installed. Rollback files: $rollback"
}

usage() {
    echo "Usage: $0 [login01|client|dc01-monitoring]"
}

role=${1-}
if [ -z "$role" ]; then
    echo "StumpfWorks Identity guided installer"
    echo "  1) LOGIN01 server"
    echo "  2) Linux native client"
    echo "  3) DC01 certificate monitoring (no Kerberos changes)"
    selection=$(ask "Select a role" "1")
    case "$selection" in 1) role=login01 ;; 2) role=client ;; 3) role=dc01-monitoring ;; *) usage; exit 2 ;; esac
fi

case "$role" in
    login01) install_login01 ;;
    client|wyse01) install_client ;;
    dc01-monitoring) install_dc_monitoring ;;
    *) usage; exit 2 ;;
esac
