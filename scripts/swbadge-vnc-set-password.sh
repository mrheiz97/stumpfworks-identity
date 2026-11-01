#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v x11vnc >/dev/null 2>&1 || { echo "x11vnc is not installed." >&2; exit 1; }

# The client installer shares this directory with the lightdm greeter. Do not
# change an existing directory's owner/mode: 0700 would hide client.conf and
# repeatedly terminate the display (and therefore VNC). The password itself
# remains root-only below.
if [ -L /etc/stumpfworks-badge ] || { [ -e /etc/stumpfworks-badge ] && [ ! -d /etc/stumpfworks-badge ]; }; then
    echo "Client configuration path must be a real directory." >&2
    exit 1
fi
if [ ! -d /etc/stumpfworks-badge ]; then
    install -d -o root -g root -m 0700 /etc/stumpfworks-badge
else
    directory_owner=$(stat -c '%u' /etc/stumpfworks-badge)
    directory_mode=$(stat -c '%a' /etc/stumpfworks-badge)
    if [ "$directory_owner" != 0 ] || [ "$((0$directory_mode & 0022))" -ne 0 ]; then
        echo "Client configuration directory must be root-owned and not writable by group or others." >&2
        exit 1
    fi
fi
password_tmp=$(mktemp /etc/stumpfworks-badge/.vnc.passwd.XXXXXX)
trap 'rm -f "$password_tmp"' EXIT INT TERM

echo "Enter a strong VNC password with exactly 8 characters."
echo "Classic VNC authentication ignores or rejects characters beyond byte 8."
echo "The password is entered at the protected prompt and is never printed or logged."
x11vnc -storepasswd "$password_tmp"
install -o root -g root -m 0600 "$password_tmp" /etc/stumpfworks-badge/vnc.passwd
rm -f "$password_tmp"
trap - EXIT INT TERM

systemctl enable --now swbadge-vnc.service
systemctl --no-pager --full status swbadge-vnc.service
