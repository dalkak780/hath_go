package hath

// Certificate handling: the client fetches a server-issued PKCS#12 bundle via
// the get_cert RPC and uses it as its TLS server identity, so it can serve
// content as a trusted edge node on hath.network. The private key's password
// is the client key.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const certFile = "hathcert.p12"

// CertManager owns the server-issued TLS identity.
type CertManager struct {
	settings *Settings
	cert     tls.Certificate
	leaf     *x509.Certificate
	expiry   time.Time
}

// LoadOrRefresh fetches the PKCS#12 via get_cert and parses it into a
// tls.Certificate. Returns an error if the cert is missing or expired.
func (c *CertManager) LoadOrRefresh(rpc *ServerHandler) error {
	path := filepath.Join(c.settings.DataDir, certFile)
	Info("requesting certificate from server...")
	if err := rpc.GetCertificate(path); err != nil {
		return err
	}
	p12, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	priv, leaf, caCerts, err := pkcs12.DecodeChain(p12, c.settings.ClientKey)
	if err != nil {
		return err
	}
	chain := make([][]byte, 0, 1+len(caCerts))
	chain = append(chain, leaf.Raw)
	for _, ca := range caCerts {
		chain = append(chain, ca.Raw)
	}
	c.leaf = leaf
	c.expiry = leaf.NotAfter
	c.cert = tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        leaf,
	}
	Debug("loaded keystore", "subject", leaf.Subject.String())
	if c.IsExpired() {
		return errors.New("retrieved certificate is expired (check system clock)")
	}
	return nil
}

// IsExpired is true if the cert expires within 24h (matches the original check).
func (c *CertManager) IsExpired() bool {
	return c.expiry.Before(time.Now().Add(24 * time.Hour))
}

// TLSConfig builds the server TLS config (TLS 1.2 / 1.3 only).
func (c *CertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{c.cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
}
