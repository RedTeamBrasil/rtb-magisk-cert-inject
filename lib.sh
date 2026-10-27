#!/system/bin/sh
# lib.sh — shared logic for the Cert Inject Magisk module.
#
# Sourced by post-fs-data.sh, service.sh and customize.sh. The caller must set
# MODDIR to the module directory before sourcing (post-fs-data/service derive
# it from $0; customize.sh uses $MODPATH).
#
# Paths can be overridden for a safe dry run:
#   APEX_DIR=/data/local/tmp/fakeapex SYS_DIR=/data/local/tmp/fakesys \
#   USER_CERT_DIRS=/data/local/tmp/fakeuser ./post-fs-data.sh

MODDIR="${MODDIR:-${0%/*}}"
APEX_DIR="${APEX_DIR:-/apex/com.android.conscrypt/cacerts}"
SYS_DIR="${SYS_DIR:-/system/etc/security/cacerts}"

DATA="${DATA:-/data/adb/cert-inject}"
STAGE="$DATA/stage"
APEX_STORE="$DATA/apex-store"
MANIFEST="$DATA/injected.txt"
LOG="$DATA/inject.log"

mkdir -p "$DATA" 2>/dev/null

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Magisk installs module files as 0644, so the helper binaries must be made
# executable before use. Also picks the binary that matches this CPU.
prepare_helper() {
	case "$(uname -m)" in
		aarch64|arm64) HELPER="$MODDIR/bin/certinject-arm64" ;;
		armv8l|armv7l|arm) HELPER="$MODDIR/bin/certinject-arm" ;;
		x86_64|amd64) HELPER="$MODDIR/bin/certinject-x86_64" ;;
		*) log "ERROR: unsupported architecture: $(uname -m)"; return 1 ;;
	esac
	[ -f "$HELPER" ] || { log "ERROR: missing $HELPER"; return 1; }
	chmod 755 "$MODDIR/bin/"* 2>/dev/null
	[ -x "$HELPER" ] || { log "ERROR: cannot execute $HELPER"; return 1; }
	return 0
}

user_cert_dirs() {
	if [ -n "$USER_CERT_DIRS" ]; then
		echo "$USER_CERT_DIRS"
		return 0
	fi
	for d in /data/misc/user/*/cacerts-added /data/misc/keychain/cacerts-added; do
		[ -d "$d" ] && echo "$d"
	done
}

# Rebuild $STAGE from every certificate in the user stores. The helper writes
# each certificate under BOTH trust-store names, always as PEM.
build_stage() {
	rm -rf "$STAGE"
	mkdir -p "$STAGE"
	found=0
	for d in $(user_cert_dirs); do
		for f in "$d"/*; do
			[ -f "$f" ] || continue
			if "$HELPER" -q -o "$STAGE" "$f"; then
				found=$((found + 1))
			else
				log "WARN: cannot parse $f"
			fi
		done
	done
	count=$(stage_names | wc -l | tr -d ' ')
	log "staged $count trust-store name(s) from $found input file(s)"
	return 0
}

stage_names() {
	ls "$STAGE" 2>/dev/null | grep -E '^[0-9a-f]{8}\.0$'
}

# Magisk magic-mounts each module file as a read-only bind mount, so a plain
# cp/rm on the live path fails with EROFS even after `remount,rw` of the parent
# tmpfs. Unmount the individual file first; the tmpfs then exposes a writable
# (usually zero-length) placeholder that can be replaced.
unmount_file() {
	if mount | grep -Fq " on $1 "; then
		umount "$1" 2>/dev/null
	fi
}

# Remove files we injected on a previous run that are no longer in $STAGE
# (the user removed the certificate). Native CAs are never in the manifest.
prune_old() {
	dir="$1"
	[ -f "$MANIFEST" ] || return 0
	while IFS= read -r h; do
		[ -n "$h" ] || continue
		if [ ! -f "$STAGE/$h" ] && [ -e "$dir/$h" ]; then
			unmount_file "$dir/$h"
			rm -f "$dir/$h"
			log "pruned $dir/$h"
		fi
	done < "$MANIFEST"
}

# Copy $STAGE into DIR with the ownership, mode and SELinux label the CA
# stores require. Only touches the files it writes.
install_into() {
	dir="$1"
	[ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null
	for f in "$STAGE"/*.0; do
		[ -f "$f" ] || continue
		b=${f##*/}
		dst="$dir/$b"
		unmount_file "$dst"
		cp -f "$f" "$dst" || { log "WARN: cannot write $dst"; continue; }
		chown 0:0 "$dst" 2>/dev/null
		chmod 644 "$dst" 2>/dev/null
		chcon u:object_r:system_security_cacerts_file:s0 "$dst" 2>/dev/null
	done
}

# The module's own system/ tree is the source Magisk magic-mounts on boot.
# It contains only our files, so anything not in the stage is stale.
#
# The marker matters: Magisk only creates the tmpfs that makes the live /system
# store writable when the module directory has at least one entry. On a clean
# device the user store is empty, so without it the store would stay read-only
# until a reboot and certificates added afterwards would only reach /apex.
# The marker is inert: consumers index that directory by "<8 hex>.0", so a
# dotfile is never parsed as a certificate.
sync_module_store() {
	dir="$MODDIR/system/etc/security/cacerts"
	mkdir -p "$dir" 2>/dev/null
	for f in "$dir"/*.0; do
		[ -f "$f" ] || continue
		b=${f##*/}
		[ -f "$STAGE/$b" ] || rm -f "$f"
	done
	install_into "$dir"
	: > "$dir/.cert-inject"
	chmod 644 "$dir/.cert-inject" 2>/dev/null
	chcon u:object_r:system_security_cacerts_file:s0 "$dir/.cert-inject" 2>/dev/null
	chcon u:object_r:system_security_cacerts_file:s0 "$dir" 2>/dev/null
}

# /system/etc/security/cacerts is read-only on the real partition. When Magisk
# has magic-mounted a tmpfs there (because this module ships files for it), we
# can remount it rw in this namespace and add/remove files live. The tmpfs
# superblock is shared with every namespace, so apps see the change.
sync_system_live() {
	dir="$SYS_DIR"
	[ -d "$dir" ] || return 0
	if ! mount -o remount,rw "$dir" 2>/dev/null; then
		log "system store: not writable here (applies on next boot)"
		return 0
	fi
	prune_old "$dir"
	install_into "$dir"
	mount -o remount,ro "$dir" 2>/dev/null

	missing=0
	for f in "$STAGE"/*.0; do
		[ -f "$f" ] || continue
		b=${f##*/}
		[ -s "$dir/$b" ] || missing=$((missing + 1))
	done
	if [ "$missing" -eq 0 ]; then
		log "system store: synced live"
	else
		log "system store: $missing file(s) pending (applies on next boot)"
	fi
}

# /apex is read-only, so clone the store into a private tmpfs and bind-mount
# it over the real directory. Keeping the tmpfs mounted means later updates
# only need to copy files into $APEX_STORE — no remount required.
setup_apex() {
	apex="$APEX_DIR"
	[ -d "$apex" ] || { log "apex store: not present"; return 0; }

	if [ -f "$APEX_STORE/.cert-inject" ]; then
		prune_old "$APEX_STORE"
		install_into "$APEX_STORE"
	else
		# A previous run may have left the tmpfs mounted (interrupted before
		# the marker was written). Drop it so we start from a clean clone.
		if mount | grep -q " on $APEX_STORE "; then
			umount -l "$APEX_STORE" 2>/dev/null
		fi
		rm -rf "$APEX_STORE" 2>/dev/null
		mkdir -p "$APEX_STORE" || { log "ERROR: cannot create $APEX_STORE"; return 1; }
		mount -t tmpfs tmpfs "$APEX_STORE" || { log "ERROR: tmpfs mount failed"; return 1; }
		cp -a "$apex"/. "$APEX_STORE"/ || { log "ERROR: clone failed"; return 1; }

		n=$(ls "$APEX_STORE" | grep -cE '^[0-9a-f]{8}\.0$')
		if [ "$n" -lt 100 ]; then
			log "ERROR: clone looks incomplete ($n certs); refusing to hide the real store"
			umount "$APEX_STORE" 2>/dev/null
			return 1
		fi

		prune_old "$APEX_STORE"
		install_into "$APEX_STORE"
		: > "$APEX_STORE/.cert-inject"
		chmod 755 "$APEX_STORE"
		chcon -R u:object_r:system_security_cacerts_file:s0 "$APEX_STORE" 2>/dev/null
		log "apex store: cloned $n native cert(s) into tmpfs"
	fi

	# Bind into the current namespace, then into init and zygote so processes
	# that already unshared their mount namespace see it too.
	if [ ! -f "$apex/.cert-inject" ]; then
		mount --bind "$APEX_STORE" "$apex" 2>/dev/null || log "WARN: bind failed in current namespace"
	fi
	for pid in 1 $(pgrep zygote 2>/dev/null) $(pgrep zygote64 2>/dev/null); do
		[ -d "/proc/$pid/ns/mnt" ] || continue
		if [ ! -f "/proc/$pid/root${apex}/.cert-inject" ] 2>/dev/null; then
			nsenter --mount="/proc/$pid/ns/mnt" -- /bin/mount --bind "$APEX_STORE" "$apex" 2>/dev/null
		fi
	done

	n=$(ls "$APEX_STORE" | grep -cE '^[0-9a-f]{8}\.0$')
	log "apex store: $n cert(s) visible"
}

write_manifest() {
	stage_names > "$MANIFEST.tmp" 2>/dev/null
	mv -f "$MANIFEST.tmp" "$MANIFEST" 2>/dev/null
}

run_injection() {
	prepare_helper || return 1
	build_stage
	sync_module_store
	sync_system_live
	setup_apex
	write_manifest
	return 0
}
