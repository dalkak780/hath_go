package hath

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

// genCertWithNotAfter builds a self-signed leaf with the given expiry.
func genCertWithNotAfter(t *testing.T, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hath.network"},
		NotBefore:    notAfter.Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf, key
}

// genCert builds a self-signed leaf + key valid for ~1 year.
func genCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hath.network"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf, key
}

func TestCertManagerTLSConfig(t *testing.T) {
	leaf, key := genCert(t)
	tlsCert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	cm := &CertManager{cert: tlsCert, leaf: leaf, expiry: leaf.NotAfter}
	cfg := cm.TLSConfig()
	if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions wrong: min=%d max=%d", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(cfg.Certificates))
	}
}

func TestCertManagerExpiry(t *testing.T) {
	leaf, _ := genCert(t)
	cm := &CertManager{leaf: leaf, expiry: leaf.NotAfter}
	if cm.IsExpired() {
		t.Fatal("future cert should not be expired")
	}
	cm.expiry = time.Now().Add(-time.Hour)
	if !cm.IsExpired() {
		t.Fatal("past expiry should be expired")
	}
}

func TestCertLoadOrRefresh(t *testing.T) {
	leaf, key := genCert(t)
	ca, _ := genCert(t)
	// Java KeyStore exports may include CA safe bags in addition to the leaf
	// and private key. DecodeChain must accept and preserve those certificates.
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, []*x509.Certificate{ca}, testClientKey)
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}
	m, s, rpc := newMockRPC(t)
	m.certBytes = p12
	dir := t.TempDir()
	s.DataDir = dir
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err != nil {
		t.Fatalf("LoadOrRefresh failed: %v", err)
	}
	if cm.leaf == nil || cm.leaf.Subject.CommonName != "hath.network" {
		t.Fatalf("leaf not parsed: %+v", cm.leaf)
	}
	if got := len(cm.cert.Certificate); got != 2 {
		t.Fatalf("certificate chain length = %d, want 2", got)
	}
	if cm.IsExpired() {
		t.Fatal("fresh cert should not be expired")
	}
	if cm.TLSConfig() == nil {
		t.Fatal("TLSConfig should be non-nil")
	}
	_ = m
}
