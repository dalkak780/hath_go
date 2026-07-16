package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestInspect(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hath.network"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pfx, err := pkcs12.LegacyRC2.WithIterations(2048).Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	r, err := inspect(pfx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !r.DecodeOK || len(r.Certificates) != 1 || !r.Certificates[0].KeyMatch {
		t.Fatalf("unexpected report: %+v", r)
	}
}
