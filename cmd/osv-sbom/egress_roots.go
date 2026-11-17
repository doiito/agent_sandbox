package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

func verifyEgressRoots(bundle, source, license []byte) (string, int, error) {
	var lock struct {
		Protocol         string `json:"protocol"`
		Version          string `json:"version"`
		SHA256           string `json:"sha256"`
		CertificateCount int    `json:"certificate_count"`
		License          string `json:"license"`
		LicenseSHA256    string `json:"license_sha256"`
	}
	if json.Unmarshal(source, &lock) != nil || lock.Protocol != "osv-egress-public-roots/v1" || lock.Version == "" || lock.License != "MPL-2.0" {
		return "", 0, errors.New("invalid public roots source lock")
	}
	digest, licenseDigest := sha256.Sum256(bundle), sha256.Sum256(license)
	if hex.EncodeToString(digest[:]) != lock.SHA256 || hex.EncodeToString(licenseDigest[:]) != lock.LicenseSHA256 {
		return "", 0, errors.New("public roots or license hash mismatch")
	}
	count := 0
	data := bundle
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			return "", 0, errors.New("unexpected public roots PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return "", 0, errors.New("invalid CA certificate")
		}
		count++
	}
	if count != lock.CertificateCount || count < 1 {
		return "", 0, errors.New("public roots certificate count mismatch")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return "", 0, errors.New("public roots cannot be loaded")
	}
	return lock.Version, count, nil
}
func egressRootsComponents(bundlePath, sourcePath, licensePath string) []component {
	bundle, e1 := os.ReadFile(bundlePath)
	source, e2 := os.ReadFile(sourcePath)
	license, e3 := os.ReadFile(licensePath)
	if e1 != nil || e2 != nil || e3 != nil {
		fatalf("cannot read public roots bundle/provenance/license")
	}
	version, _, err := verifyEgressRoots(bundle, source, license)
	if err != nil {
		fatalf("%v", err)
	}
	ca := fileComponent("egress-public-ca-bundle", bundlePath)
	ca.Version = version
	ca.Licenses = []licenseChoice{{Expression: "MPL-2.0"}}
	return []component{ca, fileComponent("egress-public-ca-source-lock", sourcePath), fileComponent("egress-public-ca-license", licensePath)}
}
