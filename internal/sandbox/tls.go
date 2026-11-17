package sandbox

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

func LoadServerTLS(config *TLSConfig) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("TLS configuration is required")
	}
	keyInfo, err := os.Stat(config.KeyFile)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("TLS private key must be a regular file inaccessible to other users")
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse TLS server certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("TLS server certificate is not currently valid")
	}
	certificate.Leaf = leaf
	clientCA, err := os.ReadFile(config.ClientCAFile)
	if err != nil {
		return nil, err
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("client CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{certificate},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientPool,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}, nil
}
