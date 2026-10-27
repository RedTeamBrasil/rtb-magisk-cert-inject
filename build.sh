#!/bin/sh
# build.sh — cross-compile the helper and pack the Magisk module.
#
# Produces dist/cert-inject-v<version>.zip, ready for `magisk --install-module`
# or the Magisk app's "Install from storage".
set -eu
cd "$(dirname "$0")"

VERSION=$(sed -n 's/^version=//p' module.prop)
OUT=dist
NAME="cert-inject-${VERSION}.zip"

mkdir -p bin "$OUT"

build() {
	goos=$1 goarch=$2 goarm=$3 out=$4
	echo "  building $out (linux/$goarch${goarm:+/$goarm})"
	GOOS=$goos GOARCH=$goarch GOARM=$goarm CGO_ENABLED=0 \
		go build -trimpath -ldflags='-s -w' -o "bin/$out" ./src
}

echo "[1/4] helper binaries"
build linux arm64 "" certinject-arm64
build linux arm 7 certinject-arm
build linux amd64 "" certinject-x86_64
chmod 755 bin/certinject-*

echo "[2/4] host binary for the self-test"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$OUT/certinject-host" ./src

echo "[3/4] self-test"
check_cert() {
	file=$1
	label=$2
	want=$(openssl x509 -in "$file" -noout -subject_hash -subject_hash_old 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
	if [ -z "$want" ]; then
		want=$(openssl x509 -inform DER -in "$file" -noout -subject_hash -subject_hash_old 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
	fi
	[ -n "$want" ] || { echo "  SELF-TEST FAILED ($label): openssl could not read the cert"; exit 1; }
	got=$("$OUT/certinject-host" -names "$file")
	echo "  $label: got='$got' want='$want'"
	[ "$got" = "$want" ] || { echo "  SELF-TEST FAILED ($label)"; exit 1; }
}

if command -v openssl >/dev/null 2>&1; then
	# Synthetic CA: always available, including in CI. The subject mixes case
	# and a double space, so it exercises OpenSSL's canonical subject encoding
	# (UTF-8, lowercase, collapsed whitespace) rather than the raw DER.
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-subj "/C=BR/ST=SP/L=Sao Paulo/O=Cert  Inject/OU=CI/CN=cert-inject.test" \
		-keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
	check_cert "$tmp/cert.pem" "synthetic (PEM)"
	openssl x509 -in "$tmp/cert.pem" -outform DER -out "$tmp/cert.der"
	check_cert "$tmp/cert.der" "synthetic (DER)"
	# Reference CA from a local checkout; not shipped in the repo.
	if [ -f ../burp.pem ]; then
		check_cert ../burp.pem "burp.pem"
		[ -f ../cacert.cer ] && check_cert ../cacert.cer "cacert.cer (DER)"
	fi
else
	echo "  skipped (openssl not available)"
fi

echo "[4/4] packing $OUT/$NAME"
rm -f "$OUT/$NAME"
zip -qr9 "$OUT/$NAME" \
	module.prop \
	customize.sh \
	post-fs-data.sh \
	service.sh \
	uninstall.sh \
	lib.sh \
	README.md \
	bin \
	src \
	META-INF
echo "  -> $OUT/$NAME ($(du -h "$OUT/$NAME" | cut -f1))"
