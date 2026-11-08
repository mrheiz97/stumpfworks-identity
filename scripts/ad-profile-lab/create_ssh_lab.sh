#!/bin/sh
set -eu
umask 077

lab=/tmp/create-ssh-lab
relay=/workspace/dist/ad-profile-tests/ad-create-ssh-relay
test "$(id -u)" -eq 0
test "$(ls /sys/class/net)" = lo
test "${IDENTITY_CREATE_SSH_LAB:-}" = 1
mkdir -m 0755 "$lab"
mkdir -m 0755 /etc/create-ssh-lab
mkdir -m 0750 "$lab/dc" "$lab/login"
chown 0:65531 "$lab/dc"
chown 65532:65534 "$lab/login"
groupadd -g 65531 create-ssh-dc
useradd -u 65531 -g 65531 -M -s /bin/sh -p '*' create-ssh-dc
useradd -u 65532 -g 65534 -M -s /usr/sbin/nologin create-ssh-login
ssh-keygen -q -t ed25519 -N '' -f "$lab/host"
ssh-keygen -q -t ed25519 -N '' -f "$lab/client"
ssh-keygen -q -t ed25519 -N '' -f "$lab/wrong"
chown 65532 "$lab/client"
printf '[127.0.0.1]:22222 %s\n' "$(cat "$lab/host.pub")" > "$lab/known_hosts"
printf '[127.0.0.1]:22222 %s\n' "$(cat "$lab/wrong.pub")" > "$lab/wrong_hosts"
printf 'restrict,from="127.0.0.1",command="%s -mode dc -config %s/dc.json" %s\n' \
    "$relay" "$lab" "$(cat "$lab/client.pub")" > /etc/create-ssh-lab/create-ssh-dc
cat > "$lab/dc.json" <<'EOF'
{"IPC":{"Enabled":true,"Socket":"/tmp/create-ssh-lab/dc/executor.sock","Owner":{"UID":0,"GID":65531},"Peer":{"UID":0,"GID":0}}}
EOF
cat > "$lab/login.json" <<'EOF'
{"IPC":{"Enabled":true,"Socket":"/tmp/create-ssh-lab/login/relay.sock","Owner":{"UID":65532,"GID":65534},"Peer":{"UID":65534,"GID":65534}},"SSH":{"Host":"127.0.0.1","Port":22222,"User":"create-ssh-dc","IdentityFile":"/tmp/create-ssh-lab/client","KnownHostsFile":"/tmp/create-ssh-lab/known_hosts"}}
EOF
chmod 0644 "$lab/dc.json" "$lab/login.json" "$lab/known_hosts" /etc/create-ssh-lab/create-ssh-dc
cat > "$lab/sshd.conf" <<'EOF'
Port 22222
ListenAddress 127.0.0.1
HostKey /tmp/create-ssh-lab/host
AuthorizedKeysFile /etc/create-ssh-lab/%u
AllowUsers create-ssh-dc
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
UsePAM no
DisableForwarding yes
PermitTTY no
LogLevel VERBOSE
EOF
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f "$lab/sshd.conf" > "$lab/sshd.log" 2>&1 &
sshd_pid=$!
relay_pid=
cleanup() {
    rc=$?
    trap - EXIT
    if [ -n "$relay_pid" ]; then kill "$relay_pid" 2>/dev/null || true; wait "$relay_pid" || true; fi
    kill "$sshd_pid" 2>/dev/null || true
    wait "$sshd_pid" || true
    if [ "$rc" -ne 0 ]; then tail -n 35 "$lab/sshd.log"; fi
    exit "$rc"
}
trap cleanup EXIT
python3 -B - <<'PY'
import socket, time
for _ in range(40):
    try:
        with socket.create_connection(("127.0.0.1", 22222), .2):
            break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit("isolated sshd did not start")
PY
denied_ssh() {
    code=0
    ssh -F /dev/null -T -p 22222 -i "$1" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$2" -o GlobalKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 create-ssh-dc@127.0.0.1 </dev/null >/dev/null 2>"$lab/denied.log" || code=$?
    test "$code" -eq 255
}
denied_ssh "$lab/client" "$lab/wrong_hosts"
grep -qi 'host key verification failed' "$lab/denied.log"
denied_ssh "$lab/wrong" "$lab/known_hosts"
grep -qi 'permission denied (publickey)' "$lab/denied.log"
setpriv --reuid=65532 --regid=65534 --clear-groups "$relay" -mode login -config "$lab/login.json" &
relay_pid=$!
for n in $(seq 1 40); do
    test ! -S "$lab/login/relay.sock" || break
    kill -0 "$relay_pid"
    sleep 0.1
done
test -S "$lab/login/relay.sock"
/workspace/dist/ad-profile-tests/adprofile.test -test.v -test.run '^TestCreateIdentityLab$'
kill "$relay_pid"
wait "$relay_pid"
relay_pid=
python3 -B - <<'PY'
import socket
with socket.socket(socket.AF_UNIX) as connection:
    try:
        connection.connect("/tmp/create-ssh-lab/login/relay.sock")
    except ConnectionRefusedError:
        pass
    else:
        raise SystemExit("stopped relay still accepts requests")
PY
mv /etc/create-ssh-lab/create-ssh-dc "$lab/revoked-key"
denied_ssh "$lab/client" "$lab/known_hosts"
grep -qi 'permission denied (publickey)' "$lab/denied.log"
test -s /tmp/native-cas/create-identity.db
printf 'SSH relay transport, key rejection and shutdown passed\n'
