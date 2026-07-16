package hath

// Certificate handling: the client fetches a server-issued PKCS#12 bundle via
// the get_cert RPC and uses it as its TLS server identity, so it can serve
// content as a trusted edge node on hath.network. The private key's password
// is the client key.

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const certFile = "hathcert.p12"

// CertManager owns the server-issued TLS identity.
type CertManager struct {
	settings *Settings
	mu       sync.RWMutex
	cert     tls.Certificate
	leaf     *x509.Certificate
	expiry   time.Time
}

// LoadOrRefresh fetches the PKCS#12 via get_cert and parses it into a
// tls.Certificate. Returns an error if the cert is missing or expired.
func (c *CertManager) LoadOrRefresh(rpc *ServerHandler) error {
	path := filepath.Join(c.settings.DataDir, certFile)
	tmp := path + ".new"
	defer os.Remove(tmp)
	Info("requesting certificate from server...")
	if err := rpc.GetCertificate(tmp); err != nil {
		return err
	}
	p12, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	priv, leaf, caCerts, err := pkcs12.DecodeChain(p12, c.settings.ClientKey)
	if err != nil {
		return err
	}
	all := append([]*x509.Certificate{leaf}, caCerts...)
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("PKCS#12 private key cannot sign")
	}
	pub, _ := x509.MarshalPKIXPublicKey(signer.Public())
	for _, candidate := range all {
		candidatePub, _ := x509.MarshalPKIXPublicKey(candidate.PublicKey)
		if bytes.Equal(pub, candidatePub) {
			leaf = candidate
			break
		}
	}
	leafPub, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !bytes.Equal(pub, leafPub) {
		return errors.New("PKCS#12 has no certificate associated with its private key")
	}

	ordered := []*x509.Certificate{leaf}
	used := map[*x509.Certificate]bool{leaf: true}
	for current := leaf; !bytes.Equal(current.RawIssuer, current.RawSubject); {
		var issuer *x509.Certificate
		for _, candidate := range all {
			if !used[candidate] && bytes.Equal(current.RawIssuer, candidate.RawSubject) && current.CheckSignatureFrom(candidate) == nil {
				issuer = candidate
				break
			}
		}
		if issuer == nil {
			break
		}
		ordered = append(ordered, issuer)
		used[issuer] = true
		current = issuer
	}
	chain := make([][]byte, 0, len(ordered))
	for _, cert := range ordered {
		chain = append(chain, cert.Raw)
	}
	cert := tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        leaf,
	}
	if leaf.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
		return errors.New("retrieved certificate is expired (check system clock)")
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	c.mu.Lock()
	c.leaf, c.expiry, c.cert = leaf, leaf.NotAfter, cert
	c.mu.Unlock()
	Debug("loaded keystore", "subject", leaf.Subject.String())
	return nil
}

// IsExpired is true if the cert expires within 24h (matches the original check).
func (c *CertManager) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.expiry.Before(time.Now().Add(24 * time.Hour))
}

// TLSConfig builds the server TLS config (TLS 1.2 / 1.3 only).
func (c *CertManager) TLSConfig() *tls.Config {
	c.mu.RLock()
	initial := c.cert
	c.mu.RUnlock()
	return &tls.Config{
		Certificates: []tls.Certificate{initial},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c.mu.RLock()
			defer c.mu.RUnlock()
			return &c.cert, nil
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}
