#!/bin/sh
set -eu
umask 077
export IDENTITY_AD_PROFILE_LAB=/tmp/lab-config.json
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
python3 -B /workspace/scripts/ad-profile-lab/native_setup.py
dc_pid=
stop_dc() {
 if [ -n "$dc_pid" ]; then
  python3 -B /workspace/scripts/ad-profile-lab/native_research.py stop-group "$dc_pid"
  wait "$dc_pid" 2>/dev/null || true
  dc_pid=
 fi
}
trap stop_dc EXIT
start_dc() {
 setsid samba --foreground --no-process-group --configfile=/tmp/profile-domain/etc/smb.conf >>/tmp/native-samba.log 2>&1 &
 dc_pid=$!
 ready=0
 for n in $(seq 1 40); do
  if kill -0 "$dc_pid" 2>/dev/null && LDAPTLS_CACERT=/tmp/ca.pem ldapsearch -x -H ldaps://dc1.profile.test -s base -b '' supportedControl >/dev/null 2>&1 && kill -0 "$dc_pid" 2>/dev/null; then ready=1; break; fi
  sleep 1
 done
 if [ "$ready" != 1 ]; then tail -n 20 /tmp/native-samba.log; exit 1; fi
}
start_dc
case "${IDENTITY_NATIVE_CRASH_CASE:-}" in
 '') python3 -B /workspace/scripts/ad-profile-lab/native_research.py ;;
 before_commit|after_commit)
  python3 -B /workspace/scripts/ad-profile-lab/native_research.py crash-trigger "$IDENTITY_NATIVE_CRASH_CASE"
  stop_dc
  # Fixed private laboratory file; no request selects this path or crash mode.
  rm /tmp/native-cas/fault
  start_dc
  python3 -B /workspace/scripts/ad-profile-lab/native_research.py crash-verify
  ;;
 *) echo 'invalid synthetic crash case' >&2; exit 1 ;;
esac
if grep -Eq 'runtime error:|UndefinedBehaviorSanitizer' /tmp/native-samba.log; then
 echo 'native sanitizer diagnostic detected' >&2
 exit 1
fi
