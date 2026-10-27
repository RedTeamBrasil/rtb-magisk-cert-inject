#!/system/bin/sh
# uninstall.sh — best-effort cleanup.
#
# The bind mount over the APEX store disappears on reboot, but unmounting it
# now stops trusting the injected CAs immediately.

umount /apex/com.android.conscrypt/cacerts 2>/dev/null
for pid in 1 $(pgrep zygote 2>/dev/null) $(pgrep zygote64 2>/dev/null); do
	[ -d "/proc/$pid/ns/mnt" ] || continue
	nsenter --mount="/proc/$pid/ns/mnt" -- /bin/umount /apex/com.android.conscrypt/cacerts 2>/dev/null
done

umount /data/adb/cert-inject/apex-store 2>/dev/null
rm -rf /data/adb/cert-inject
exit 0
