package hath

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

const keytoolHathNetworkP12 = "MIIEXAIBAzCCBAYGCSqGSIb3DQEHAaCCA/cEggPzMIID7zCCAUYGCSqGSIb3DQEHAaCCATcEggEzMIIBLzCCASsGCyqGSIb3DQEMCgECoIHNMIHKMGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBSiYOuOpkBoXCWZe5/HDyaI+H5ymgICJxACASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEED6REMoSxfMxZ0kZtwjuz8YEYJfwwe7mcl5qyKl7LPKO2AVy62Agv09zcMqg9vSuKpkqMuyrJDWkrcA/wY6v+Y/OzSHSriHhOfUMYB4gBw5nmJwYeEYwRPAu/8po37TFScrKkRMMahtIoZHm9MuCFXNI9TFMMCcGCSqGSIb3DQEJFDEaHhgAaABhAHQAaAAuAG4AZQB0AHcAbwByAGswIQYJKoZIhvcNAQkVMRQEElRpbWUgMTc4NDIwOTE1OTAyMjCCAqEGCSqGSIb3DQEHBqCCApIwggKOAgEAMIIChwYJKoZIhvcNAQcBMGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBQLVLV5x246hyq+rHwBCVyufCU24gICJxACASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEIN+SLIkfaRExUCjW6sZ8QqAggIQsTWS7r+EfqrNpdPVcPHTGXX0M9F0zqImI44OM8wohwi/5P+/ZJYyy0S6C4M4sMeGauIOELWSXdF1r4peZLdGtKcmm54YT5CrckeDLlzaCXyGptrHzwq0WD3mmD+dmBJSBzgD7w3SPnSLp6NJwRJ+a8fTCtogcFZDz8LG+AkcwwC7wgk5tH9kwPLMwq58Oj2+FOov4C0owVA/0X8LIzv33ORuIXDMIot26/lgGwBlsyUv5lwvQl7IEfxxCun2FN2zVjFwVJmo0Gb/Fzm9dif8Zo1rGbXDwXCgY3IMfSL7xH7wHWtDZmZxZQdBRasVzlVVQzZWgw41A0wOq1QKzLD87brfr1/lWAbQtPhovobu4Uh6PEO4DElVlirbNRIrljMgZ9qfWTfa6JymIFttny31drlOs+H8zNPfFocqJ0w6tJ4tWytLjII2yl+CbGNcI/hZksdxxYCfvrU3FBZd/wxpz2CXShoQuKuY+xkSL5AJ2HX16czcN2kftNhN/wTZIz9PKvJLhNDJqw/RsgFpDkqhrB9/8k1jcdRtRlLNpVcZs2GbfvQanpZ06Pm3t04+phYUfk5Y5HCi1ok9OkxsNyhZgtys8k4xjbSAC5YygHuCx8ZcuMGd6mfs+E+4WMkPSz9VVOMoVDAiYkMWPgF4kFBDRyWElML23aMzJsge8iV36w2+3Kw89+X63NmHtKYHikaxME0wMTANBglghkgBZQMEAgEFAAQga3zO4Tge6TElVOoF4EpfUt9SDt7sMqWycLPS9ir/nz0EFMAuX4Y2HjH3uL2tM031X9bGmuD6AgInEA=="

// Captured server PFX envelope: SHA-1 MAC (2048), three certificates in an
// RC2-40 encrypted safe (2048), and one 3DES shrouded keybag (2048).
var serverPFXEncoder = sslmate.LegacyRC2.WithIterations(2048)

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
	// Java KeyStore exports may include unrelated certificate safe bags. They
	// must be accepted but not sent as if they were part of the leaf chain.
	p12, err := serverPFXEncoder.Encode(key, leaf, []*x509.Certificate{ca}, testClientKey)
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
	if got := len(cm.cert.Certificate); got != 1 {
		t.Fatalf("certificate chain length = %d, want 1", got)
	}
	if cm.IsExpired() {
		t.Fatal("fresh cert should not be expired")
	}
	if cm.TLSConfig() == nil {
		t.Fatal("TLSConfig should be non-nil")
	}
	_ = m
}

func TestKeytoolHathNetworkAliasAndLocalKeyID(t *testing.T) {
	p12, err := base64.StdEncoding.DecodeString(keytoolHathNetworkP12)
	if err != nil {
		t.Fatal(err)
	}
	m, s, rpc := newMockRPC(t)
	m.certBytes = p12
	s.DataDir = t.TempDir()
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err != nil {
		t.Fatal(err)
	}
	if cm.leaf.Subject.CommonName != "hath.network" {
		t.Fatalf("wrong alias certificate: %s", cm.leaf.Subject)
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, certFile)); err != nil {
		t.Fatal(err)
	}
}

func TestPKCS12ChainServedInIssuerOrder(t *testing.T) {
	now := time.Now()
	newCA := func(name string, serial int64, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, key
	}
	trustAnchor, trustAnchorKey := newCA("omitted trust anchor", 9, nil, nil)
	lastSupplied, lastSuppliedKey := newCA("last supplied", 10, trustAnchor, trustAnchorKey)
	intermediate, intermediateKey := newCA("intermediate", 11, lastSupplied, lastSuppliedKey)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "hath.network"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	// Match the decoded production bundle: three cert bags, with the trust
	// anchor above the last supplied certificate intentionally omitted.
	p12, err := serverPFXEncoder.Encode(leafKey, leaf, []*x509.Certificate{lastSupplied, intermediate}, testClientKey)
	if err != nil {
		t.Fatal(err)
	}
	m, s, rpc := newMockRPC(t)
	m.certBytes, s.DataDir = p12, t.TempDir()
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err != nil {
		t.Fatal(err)
	}
	if len(cm.cert.Certificate) != 3 {
		t.Fatalf("chain length=%d", len(cm.cert.Certificate))
	}
	s.ClientPort = 0
	hs := &HTTPServer{settings: s, cert: cm, flood: make(map[string]*floodEntry)}
	hs.AllowNormalConnections()
	if err := hs.Start(); err != nil {
		t.Fatal(err)
	}
	defer hs.Shutdown()
	port := hs.listener.Addr().(*net.TCPAddr).Port
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := conn.ConnectionState().PeerCertificates
	if len(peer) != 3 || peer[0].Subject.CommonName != "hath.network" || peer[1].Subject.CommonName != "intermediate" || peer[2].Subject.CommonName != "last supplied" {
		t.Fatalf("served chain order wrong: %v", peer)
	}
}
