#!/system/bin/sh
# service.sh — runs in the late_start service stage.
#
# Magisk runs service scripts in a copy of the mount namespace made before
# post-fs-data, so the tmpfs store created there is not visible here. Re-exec
# inside init's namespace (a no-op if we are already there) before touching
# the stores.
#
# No `exec`: if this script is ever sourced instead of executed, `exec` would
# replace the parent boot shell. Run the child in the foreground and exit.
if [ "$1" != "--in-init-ns" ]; then
	case "$0" in
		/*) SELF=$0 ;;
		*) SELF=$(cd "$(dirname "$0")" 2>/dev/null && pwd)/$(basename "$0") ;;
	esac
	if [ -x /system/bin/nsenter ] && [ -d /proc/1/ns/mnt ]; then
		nsenter --mount=/proc/1/ns/mnt -- /system/bin/sh "$SELF" --in-init-ns
		exit 0
	fi
fi

MODDIR=${0%/*}
[ -f "$MODDIR/lib.sh" ] || MODDIR=$(dirname "$0")
. "$MODDIR/lib.sh"

mkdir -p "$DATA" 2>/dev/null
exec >> "$LOG" 2>&1

i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
	sleep 2
	i=$((i + 1))
done
sleep 5

log "=== service: initial refresh ==="
run_injection

signature() {
	for d in $(user_cert_dirs); do
		for f in "$d"/*; do
			[ -f "$f" ] || continue
			stat -c '%n %s %Y' "$f" 2>/dev/null
		done
	done | md5sum 2>/dev/null
}

(
	last=$(signature)
	log "service: watching user stores (poll 20s)"
	while true; do
		sleep 20
		now=$(signature)
		[ "$now" = "$last" ] && continue
		last="$now"
		log "=== service: user store changed, re-injecting ==="
		run_injection
	done
) &

exit 0
