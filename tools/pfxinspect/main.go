package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type certReport struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SHA256       string `json:"sha256"`
	IsCA         bool   `json:"is_ca"`
	KeyMatch     bool   `json:"matches_private_key"`
	SignedByNext bool   `json:"signed_by_next,omitempty"`
}

type report struct {
	DecodeOK     bool                `json:"decode_ok"`
	KeyType      string              `json:"key_type"`
	Certificates []certReport        `json:"certificates"`
	BagHeaders   []map[string]string `json:"bag_headers,omitempty"`
}

func inspect(pfx []byte, password string) (*report, error) {
	key, leaf, cas, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	keyDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	certs := append([]*x509.Certificate{leaf}, cas...)
	r := &report{DecodeOK: true, KeyType: fmt.Sprintf("%T", key)}
	for i, cert := range certs {
		certDER, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
		fingerprint := sha256.Sum256(cert.Raw)
		cr := certReport{
			Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
			SHA256: hex.EncodeToString(fingerprint[:]),
			IsCA:   cert.IsCA, KeyMatch: bytes.Equal(keyDER, certDER),
		}
		if i+1 < len(certs) {
			cr.SignedByNext = cert.CheckSignatureFrom(certs[i+1]) == nil
		}
		r.Certificates = append(r.Certificates, cr)
	}
	blocks, err := pkcs12.ToPEM(pfx, password)
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		h := map[string]string{"type": block.Type}
		for k, v := range block.Headers {
			h[k] = v
		}
		r.BagHeaders = append(r.BagHeaders, h)
	}
	return r, nil
}

func passwordFromClientLogin(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	_, password, ok := strings.Cut(strings.TrimSpace(string(b)), "-")
	if !ok || password == "" {
		return "", errors.New("client_login must contain <ClientID>-<ClientKey>")
	}
	return password, nil
}

func main() {
	pfxPath := flag.String("pfx", "hathcert.p12", "path to the original PFX")
	loginPath := flag.String("client-login", "client_login", "path to client_login (never printed)")
	flag.Parse()
	password, err := passwordFromClientLogin(*loginPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "password:", err)
		os.Exit(1)
	}
	pfx, err := os.ReadFile(*pfxPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pfx:", err)
		os.Exit(1)
	}
	r, err := inspect(pfx, password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
