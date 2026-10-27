#!/system/bin/sh
# customize.sh — runs inside the Magisk installer, on the device, as root.
#
# Seeds the module's system/etc/security/cacerts tree with the certificates
# that already exist in the user store, so the FIRST boot after installation
# already has them (Magisk magic-mounts the module's system/ tree).

MODDIR="$MODPATH"
. "$MODDIR/lib.sh"

command -v ui_print >/dev/null 2>&1 || ui_print() { echo "$1"; }

ui_print "- Cert Inject: reading user certificates"
if prepare_helper; then
	build_stage
	sync_module_store
	write_manifest
	n=$(stage_names | wc -l | tr -d ' ')
	ui_print "- $n trust-store file(s) staged for the first boot"
else
	ui_print "! helper is not runnable on $(uname -m); nothing pre-staged"
fi

ui_print "- Reboot to activate."
ui_print "- Certificates added later are injected automatically (~20 s)."
