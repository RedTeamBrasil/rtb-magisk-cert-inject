#!/system/bin/sh
# post-fs-data.sh — runs before zygote starts, in the global mount namespace.
#
# Injects every user-installed CA into:
#   /apex/com.android.conscrypt/cacerts      (Conscrypt + BoringSSL/Dart)
#   /system/etc/security/cacerts             (legacy / explicit readers)
# and stages the same files in the module's system/ tree so Magisk magic-mounts
# them on the next boot.

MODDIR=${0%/*}
. "$MODDIR/lib.sh"

mkdir -p "$DATA" 2>/dev/null
exec >> "$LOG" 2>&1

log "=== post-fs-data: start (arch $(uname -m)) ==="
run_injection
log "=== post-fs-data: done ==="
