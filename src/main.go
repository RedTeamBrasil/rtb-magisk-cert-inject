// certinject normalizes CA certificates and installs them under every name
// Android trust stores look up.
//
// Android keeps system CAs as <hash>.0 files, but each TLS stack indexes them
// by a different hash of the certificate subject:
//
//	Conscrypt / Java (TrustedCertificateStore, OkHttp, ...)  -> subject_hash_old (MD5)
//	BoringSSL / libflutter (Dart, native code)               -> subject_hash     (SHA-1)
//
// A certificate installed under only one of those names is invisible to the
// other stack. This helper writes both, and always writes PEM (never DER),
// because some readers parse the file contents and others only accept PEM.
//
// Usage:
//
//	certinject -o DIR FILE...     write <sha1>.0 and <md5>.0 into DIR
//	certinject -names FILE...     print "<sha1> <md5>" per certificate
//
// Input may be PEM (including bundles) or DER (including concatenated DER).
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const version = "1.1"

type certResult struct {
	input   string
	subject string
	sha1    string
	md5     string
}

func main() {
	outDir := flag.String("o", "", "output directory (created if missing)")
	namesOnly := flag.Bool("names", false, "print '<sha1> <md5>' per certificate and exit")
	quiet := flag.Bool("q", false, "suppress per-file output")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-o DIR] [-names] [-q] FILE...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("certinject", version)
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if !*namesOnly && *outDir == "" {
		fmt.Fprintln(os.Stderr, "certinject: -o DIR is required (or use -names)")
		os.Exit(2)
	}
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fatal(err)
		}
	}

	var results []certResult
	failed := false

	for _, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			warn(path, err)
			failed = true
			continue
		}
		certs, err := parseCerts(data)
		if err != nil {
			warn(path, err)
			failed = true
			continue
		}
		for _, cert := range certs {
			sha1Name, md5Name := subjectHashes(cert)
			results = append(results, certResult{
				input:   path,
				subject: cert.Subject.String(),
				sha1:    sha1Name,
				md5:     md5Name,
			})
			if *namesOnly {
				fmt.Printf("%s %s\n", sha1Name, md5Name)
				continue
			}
			// Always emit PEM, with a trailing newline, regardless of input format.
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			for _, name := range []string{sha1Name, md5Name} {
				dst := filepath.Join(*outDir, name+".0")
				if err := writeFile(dst, pemBytes); err != nil {
					warn(dst, err)
					failed = true
				}
			}
		}
	}

	if !*quiet && !*namesOnly {
		for _, r := range results {
			fmt.Printf("%s -> %s.0 %s.0\n", filepath.Base(r.input), r.sha1, r.md5)
		}
	}
	if failed {
		os.Exit(1)
	}
}

// parseCerts accepts PEM bundles and DER (single or concatenated).
func parseCerts(data []byte) ([]*x509.Certificate, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		var out []*x509.Certificate
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" && block.Type != "X509 CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid PEM certificate: %w", err)
			}
			out = append(out, cert)
		}
		if len(out) == 0 {
			return nil, errors.New("no CERTIFICATE block found")
		}
		return out, nil
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("not PEM and not valid DER: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}
	return certs, nil
}

// subjectHashes reproduces the two filename hashes OpenSSL/Android use:
//
//	subject_hash     (SHA-1)  = SHA1(canonical subject), first 4 bytes LE
//	subject_hash_old (MD5)    = MD5(raw subject DER),    first 4 bytes LE
//
// The canonical subject is NOT the raw DER. OpenSSL's x509_name_canon()
// converts every string to UTF-8, trims and collapses whitespace, lowercases
// ASCII, DER-sorts the entries of each RDN and drops the outer SEQUENCE
// header. Hashing the raw DER instead yields a different (wrong) name: for the
// PortSwigger CA it gives ab413755 instead of 7bf17d07, and BoringSSL then
// never finds the certificate.
func subjectHashes(cert *x509.Certificate) (sha1Name, md5Name string) {
	s1 := sha1.Sum(canonicalName(cert.RawSubject))
	m5 := md5.Sum(cert.RawSubject)
	return littleEndianHex(s1[:]), littleEndianHex(m5[:])
}

func littleEndianHex(sum []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x", sum[3], sum[2], sum[1], sum[0])
}

// canonicalName mirrors OpenSSL's x509_name_canon() + i2d_name_canon().
func canonicalName(rawSubject []byte) []byte {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(rawSubject, &seq); err != nil {
		return rawSubject
	}

	var out []byte
	rest := seq.Bytes
	for len(rest) > 0 {
		var rdn asn1.RawValue // SET OF X509_NAME_ENTRY
		var err error
		rest, err = asn1.Unmarshal(rest, &rdn)
		if err != nil {
			return rawSubject
		}

		var entries [][]byte
		body := rdn.Bytes
		for len(body) > 0 {
			var entry asn1.RawValue // SEQUENCE { OID, value }
			body, err = asn1.Unmarshal(body, &entry)
			if err != nil {
				return rawSubject
			}

			inner := entry.Bytes
			var oidRaw asn1.RawValue
			inner, err = asn1.Unmarshal(inner, &oidRaw)
			if err != nil {
				return rawSubject
			}
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(oidRaw.FullBytes, &oid); err != nil {
				return rawSubject
			}
			var val asn1.RawValue
			if _, err := asn1.Unmarshal(inner, &val); err != nil {
				return rawSubject
			}

			oidDER, err := asn1.Marshal(oid)
			if err != nil {
				return rawSubject
			}
			entryDER, err := asn1.Marshal(asn1.RawValue{
				Class:      0,
				Tag:        16, // SEQUENCE
				IsCompound: true,
				Bytes:      append(oidDER, canonicalValue(val)...),
			})
			if err != nil {
				return rawSubject
			}
			entries = append(entries, entryDER)
		}

		// DER SET OF ordering: bytewise, shorter first on a common prefix.
		sort.Slice(entries, func(i, j int) bool {
			return bytes.Compare(entries[i], entries[j]) < 0
		})
		var content []byte
		for _, e := range entries {
			content = append(content, e...)
		}
		setDER, err := asn1.Marshal(asn1.RawValue{
			Class:      0,
			Tag:        17, // SET
			IsCompound: true,
			Bytes:      content,
		})
		if err != nil {
			return rawSubject
		}
		out = append(out, setDER...)
	}
	return out
}

// canonicalValue converts a name attribute value the way OpenSSL does. Types
// outside ASN1_MASK_CANON are copied verbatim (tag and bytes).
func canonicalValue(v asn1.RawValue) []byte {
	switch v.Tag {
	case 0x0c, // UTF8String
		0x13, // PrintableString
		0x14, // T61String
		0x16, // IA5String
		0x1a, // VisibleString
		0x1e, // BMPString
		0x1c: // UniversalString
		s := canonicalString(decodeASN1String(v))
		der, err := asn1.Marshal(asn1.RawValue{
			Class: 0,
			Tag:   12, // UTF8String
			Bytes: []byte(s),
		})
		if err != nil {
			return v.FullBytes
		}
		return der
	default:
		return v.FullBytes
	}
}

// decodeASN1String converts the supported ASN.1 string types to UTF-8.
func decodeASN1String(v asn1.RawValue) string {
	switch v.Tag {
	case 0x1e: // BMPString: UTF-16BE
		if len(v.Bytes)%2 != 0 {
			return string(v.Bytes)
		}
		u := make([]uint16, len(v.Bytes)/2)
		for i := range u {
			u[i] = uint16(v.Bytes[2*i])<<8 | uint16(v.Bytes[2*i+1])
		}
		return string(utf16.Decode(u))
	case 0x1c: // UniversalString: UTF-32BE
		if len(v.Bytes)%4 != 0 {
			return string(v.Bytes)
		}
		var b strings.Builder
		for i := 0; i+3 < len(v.Bytes); i += 4 {
			r := rune(v.Bytes[i])<<24 | rune(v.Bytes[i+1])<<16 |
				rune(v.Bytes[i+2])<<8 | rune(v.Bytes[i+3])
			b.WriteRune(r)
		}
		return b.String()
	case 0x14: // T61String: approximate as Latin-1 (OpenSSL maps it to Unicode)
		var b strings.Builder
		for _, c := range v.Bytes {
			b.WriteRune(rune(c))
		}
		return b.String()
	default: // UTF8String, PrintableString, IA5String, VisibleString
		return string(v.Bytes)
	}
}

// canonicalString trims leading/trailing whitespace, collapses internal runs
// to a single space and lowercases ASCII letters only (OpenSSL copies bytes
// with the high bit set unchanged).
func canonicalString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	started := false
	pendingSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isASCIISpace(c) {
			if started {
				pendingSpace = true
			}
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		started = true
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// writeFile writes atomically so a running app never reads a partial PEM.
func writeFile(dst string, data []byte) error {
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func warn(what string, err error) {
	fmt.Fprintf(os.Stderr, "certinject: %s: %v\n", what, err)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "certinject: %v\n", err)
	os.Exit(1)
}
