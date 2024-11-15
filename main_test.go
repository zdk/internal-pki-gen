package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewPKIGenerator(t *testing.T) {
	tests := []struct {
		name           string
		baseDomain     string
		expectedDomain string
	}{
		{
			name:           "with custom domain",
			baseDomain:     "example.com",
			expectedDomain: "example.com",
		},
		{
			name:           "with empty domain",
			baseDomain:     "",
			expectedDomain: "mydomain.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewPKIGenerator(tt.baseDomain)
			if generator.baseDomain != tt.expectedDomain {
				t.Errorf("expected domain %s, got %s", tt.expectedDomain, generator.baseDomain)
			}
		})
	}
}

func TestPKIGenerator_Generate(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	// Test successful generation
	err = generator.Generate()
	if err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	// Verify CA certificate and key files exist
	caKeyPath := filepath.Join(tempDir, "ca-test.local.key.pem")
	caCertPath := filepath.Join(tempDir, "ca-test.local.crt")
	if !fileExists(caKeyPath) {
		t.Errorf("CA key file not found: %s", caKeyPath)
	}
	if !fileExists(caCertPath) {
		t.Errorf("CA certificate file not found: %s", caCertPath)
	}

	// Verify wildcard certificate and key files exist
	certKeyPath := filepath.Join(tempDir, "wildcard.test.local.key.pem")
	certPath := filepath.Join(tempDir, "wildcard.test.local.crt")
	if !fileExists(certKeyPath) {
		t.Errorf("Wildcard key file not found: %s", certKeyPath)
	}
	if !fileExists(certPath) {
		t.Errorf("Wildcard certificate file not found: %s", certPath)
	}

	// Test certificate content
	caCert, err := loadCertificate(caCertPath)
	if err != nil {
		t.Fatalf("failed to load CA certificate: %v", err)
	}

	// Verify CA certificate properties
	if !caCert.IsCA {
		t.Error("CA certificate is not marked as CA")
	}
	if caCert.MaxPathLen != 0 || !caCert.MaxPathLenZero {
		t.Error("CA certificate MaxPathLen is not set correctly")
	}

	// Load and verify wildcard certificate
	cert, err := loadCertificate(certPath)
	if err != nil {
		t.Fatalf("failed to load wildcard certificate: %v", err)
	}

	// Verify wildcard certificate properties
	expectedDNSNames := []string{"test.local", "*.test.local"}
	if !stringSliceEqual(cert.DNSNames, expectedDNSNames) {
		t.Errorf("expected DNS names %v, got %v", expectedDNSNames, cert.DNSNames)
	}

	// Test certificate validity period
	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Error("certificate NotBefore is in the future")
	}
	if cert.NotAfter.Before(now.AddDate(0, 0, validityDays-1)) {
		t.Error("certificate NotAfter is too soon")
	}

	// Test error case: generating in existing directory with certificates
	err = generator.Generate()
	if err == nil {
		t.Error("expected error when generating certificates in directory with existing certificates")
	}
}

func TestPKIGenerator_generateCA(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pki-ca-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	ca, caPrivKey, err := generator.generateCA()
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	if ca == nil {
		t.Error("CA certificate is nil")
	}
	if caPrivKey == nil {
		t.Error("CA private key is nil")
	}

	// Verify CA key size
	if caPrivKey.Size() != caKeySize/8 {
		t.Errorf("expected CA key size %d, got %d", caKeySize/8, caPrivKey.Size())
	}
}

func TestPKIGenerator_generateWildcardCert(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pki-wildcard-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	// First generate CA
	ca, caPrivKey, err := generator.generateCA()
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Generate wildcard certificate
	err = generator.generateWildcardCert(ca, caPrivKey)
	if err != nil {
		t.Fatalf("failed to generate wildcard certificate: %v", err)
	}

	// Verify certificate files exist
	certKeyPath := filepath.Join(tempDir, "wildcard.test.local.key.pem")
	certPath := filepath.Join(tempDir, "wildcard.test.local.crt")
	if !fileExists(certKeyPath) {
		t.Errorf("Wildcard key file not found: %s", certKeyPath)
	}
	if !fileExists(certPath) {
		t.Errorf("Wildcard certificate file not found: %s", certPath)
	}
}

// Helper functions

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
