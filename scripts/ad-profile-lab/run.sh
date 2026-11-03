#!/bin/sh
set -eu
samba --version
openssl version
python3 /workspace/scripts/ad-profile-lab/provision.py >/tmp/provision.log 2>&1 || { tail -n 15 /tmp/provision.log; exit 1; }
samba --foreground --no-process-group --configfile=/tmp/profile-domain/etc/smb.conf >/tmp/samba.log 2>&1 &
dc_pid=$!
trap 'kill "$dc_pid" 2>/dev/null || true; wait "$dc_pid" 2>/dev/null || true' EXIT
ready=0
for n in $(seq 1 40); do
 if LDAPTLS_CACERT=/tmp/ca.pem ldapsearch -x -H ldaps://dc1.profile.test -s base -b '' supportedControl >/tmp/rootdse 2>/dev/null; then ready=1; break; fi
 sleep 1
done
if [ "$ready" != 1 ]; then tail -n 20 /tmp/samba.log; exit 1; fi
export IDENTITY_AD_PROFILE_LAB=/tmp/lab-config.json
/workspace/dist/ad-profile-tests/adprofile.test -test.v -test.run Samba
python3 -B /workspace/scripts/ad-profile-lab/broker_research.py
python3 -B /workspace/scripts/ad-profile-lab/broker_boundary_research.py
kill "$dc_pid"
wait "$dc_pid" || true
dc_pid=
sh /workspace/scripts/ad-profile-lab/native_run.sh
