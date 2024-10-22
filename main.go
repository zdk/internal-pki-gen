package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	validityDays = 3650 // 10 years
	caKeySize    = 4096
	certKeySize  = 2048
)

type PKIGenerator struct {
	baseDomain string
	outputDir  string
}

func NewPKIGenerator(baseDomain string) *PKIGenerator {
	if baseDomain == "" {
		baseDomain = "mydomain.internal"
	}
	return &PKIGenerator{
		baseDomain: baseDomain,
		outputDir:  "certs-and-keys",
	}
}

func (g *PKIGenerator) Generate() error {
	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate CA
	ca, caPrivKey, err := g.generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate wildcard certificate
	if err := g.generateWildcardCert(ca, caPrivKey); err != nil {
		return fmt.Errorf("failed to generate wildcard certificate: %w", err)
	}

	return nil
}

func (g *PKIGenerator) generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	caKeyPath := filepath.Join(g.outputDir, fmt.Sprintf("ca-%s.key.pem", g.baseDomain))
	caCertPath := filepath.Join(g.outputDir, fmt.Sprintf("ca-%s.crt", g.baseDomain))

	// Check if CA already exists
	if _, err := os.Stat(caKeyPath); err == nil {
		return nil, nil, fmt.Errorf("will not overwrite existing: %s", caKeyPath)
	}

	// Generate CA private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, caKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Internal"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{g.baseDomain, "." + g.baseDomain},
	}

	// Create CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save CA private key
	caKeyFile, err := os.OpenFile(caKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA key file: %w", err)
	}
	if err := pem.Encode(caKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA private key: %w", err)
	}
	caKeyFile.Close()

	// Save CA certificate
	caCertFile, err := os.OpenFile(caCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	if err := pem.Encode(caCertFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}
	caCertFile.Close()

	ca, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return ca, caPrivKey, nil
}

func (g *PKIGenerator) generateWildcardCert(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) error {
	certKeyPath := filepath.Join(g.outputDir, fmt.Sprintf("wildcard.%s.key.pem", g.baseDomain))
	certPath := filepath.Join(g.outputDir, fmt.Sprintf("wildcard.%s.crt", g.baseDomain))

	// Check if certificate already exists
	if _, err := os.Stat(certKeyPath); err == nil {
		return fmt.Errorf("will not overwrite existing: %s", certKeyPath)
	}

	// Generate certificate private key
	certPrivKey, err := rsa.GenerateKey(rand.Reader, certKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate certificate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "*." + g.baseDomain,
		},
		DNSNames: []string{
			g.baseDomain,
			"*." + g.baseDomain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate private key
	certKeyFile, err := os.OpenFile(certKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create certificate key file: %w", err)
	}
	if err := pem.Encode(certKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}); err != nil {
		return fmt.Errorf("failed to write certificate private key: %w", err)
	}
	certKeyFile.Close()

	// Save certificate
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	certFile.Close()

	// Verify certificate
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	opts := x509.VerifyOptions{
		DNSName: "*." + g.baseDomain,
		Roots:   roots,
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

func main() {
	var baseDomain string
	if len(os.Args) > 1 {
		baseDomain = os.Args[1]
	}

	generator := NewPKIGenerator(baseDomain)
	if err := generator.Generate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated certificates for %s\n", generator.baseDomain)
}
