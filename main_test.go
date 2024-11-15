package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewPKIGenerator tests the constructor of PKIGenerator
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
			if generator.outputDir != "certs-and-keys" {
				t.Errorf("expected output directory 'certs-and-keys', got %s", generator.outputDir)
			}
		})
	}
}

// TestPKIGenerator_GenerateErrorCases tests various error scenarios
func TestPKIGenerator_GenerateErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(*PKIGenerator)
		expectedError string
	}{
		{
			name: "invalid output directory permissions",
			setupFunc: func(g *PKIGenerator) {
				g.outputDir = "/root/unauthorized" // Should fail due to permissions
			},
			expectedError: "failed to create output directory",
		},
		{
			name: "existing CA certificate",
			setupFunc: func(g *PKIGenerator) {
				// Create directory and dummy CA cert
				os.MkdirAll(g.outputDir, 0755)
				dummyFile := filepath.Join(g.outputDir, "ca-"+g.baseDomain+".key.pem")
				os.WriteFile(dummyFile, []byte("dummy"), 0600)
			},
			expectedError: "failed to generate CA: will not overwrite existing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for each test
			tempDir, err := os.MkdirTemp("", "pki-error-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			generator := &PKIGenerator{
				baseDomain: "test.local",
				outputDir:  tempDir,
			}

			if tt.setupFunc != nil {
				tt.setupFunc(generator)
			}

			err = generator.Generate()
			if err == nil {
				t.Error("expected error but got none")
				return
			}

			if !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("expected error containing %q, got %v", tt.expectedError, err)
			}
		})
	}
}

// TestPKIGenerator_CertificateProperties performs detailed validation of generated certificates
func TestPKIGenerator_CertificateProperties(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pki-props-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	// Generate certificates
	if err := generator.Generate(); err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	// Load and verify CA certificate
	caCert, err := loadCertificate(filepath.Join(tempDir, "ca-test.local.crt"))
	if err != nil {
		t.Fatalf("failed to load CA certificate: %v", err)
	}

	// Detailed CA certificate checks
	t.Run("CA Certificate Properties", func(t *testing.T) {
		if !caCert.IsCA {
			t.Error("CA certificate should be marked as CA")
		}
		if caCert.MaxPathLen != 0 {
			t.Error("CA certificate should have MaxPathLen 0")
		}
		if !caCert.MaxPathLenZero {
			t.Error("CA certificate should have MaxPathLenZero set")
		}
		if len(caCert.PermittedDNSDomains) != 2 {
			t.Error("CA certificate should have exactly 2 permitted DNS domains")
		}
		expectedKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if caCert.KeyUsage != expectedKeyUsage {
			t.Errorf("CA certificate has incorrect key usage: got %v, want %v", caCert.KeyUsage, expectedKeyUsage)
		}
	})

	// Load and verify wildcard certificate
	wildcardCert, err := loadCertificate(filepath.Join(tempDir, "wildcard.test.local.crt"))
	if err != nil {
		t.Fatalf("failed to load wildcard certificate: %v", err)
	}

	// Detailed wildcard certificate checks
	t.Run("Wildcard Certificate Properties", func(t *testing.T) {
		if wildcardCert.IsCA {
			t.Error("Wildcard certificate should not be marked as CA")
		}
		expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if wildcardCert.KeyUsage != expectedKeyUsage {
			t.Errorf("Wildcard certificate has incorrect key usage: got %v, want %v", wildcardCert.KeyUsage, expectedKeyUsage)
		}
		if len(wildcardCert.ExtKeyUsage) != 1 || wildcardCert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Error("Wildcard certificate should have exactly one ExtKeyUsage of ServerAuth")
		}
		expectedDNSNames := []string{"test.local", "*.test.local"}
		if !stringSliceEqual(wildcardCert.DNSNames, expectedDNSNames) {
			t.Errorf("Wildcard certificate has incorrect DNS names: got %v, want %v", wildcardCert.DNSNames, expectedDNSNames)
		}

		// Check validity period
		expectedValidity := validityDays * 24 * time.Hour
		actualValidity := wildcardCert.NotAfter.Sub(wildcardCert.NotBefore)
		if actualValidity < expectedValidity-time.Hour || actualValidity > expectedValidity+time.Hour {
			t.Errorf("certificate validity period incorrect: got %v, want %v (±1h)", actualValidity, expectedValidity)
		}
	})
}

// TestPKIGenerator_CertificateValidation tests the certificate chain validation
func TestPKIGenerator_CertificateValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pki-validation-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	if err := generator.Generate(); err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	// Load certificates
	caCert, err := loadCertificate(filepath.Join(tempDir, "ca-test.local.crt"))
	if err != nil {
		t.Fatalf("failed to load CA certificate: %v", err)
	}

	wildcardCert, err := loadCertificate(filepath.Join(tempDir, "wildcard.test.local.crt"))
	if err != nil {
		t.Fatalf("failed to load wildcard certificate: %v", err)
	}

	// Create cert pool and verify chain
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	tests := []struct {
		name     string
		dnsName  string
		expectOK bool
	}{
		{
			name:     "valid wildcard name",
			dnsName:  "test.test.local",
			expectOK: true,
		},
		{
			name:     "valid base domain",
			dnsName:  "test.local",
			expectOK: true,
		},
		{
			name:     "invalid domain",
			dnsName:  "invalid.com",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := x509.VerifyOptions{
				DNSName:     tt.dnsName,
				Roots:       roots,
				CurrentTime: time.Now(),
			}

			_, err := wildcardCert.Verify(opts)
			if tt.expectOK && err != nil {
				t.Errorf("expected verification to succeed, got error: %v", err)
			} else if !tt.expectOK && err == nil {
				t.Error("expected verification to fail, but it succeeded")
			}
		})
	}
}

// TestPKIGenerator_FilePermissions tests the file permissions of generated certificates and keys
func TestPKIGenerator_FilePermissions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pki-perms-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := &PKIGenerator{
		baseDomain: "test.local",
		outputDir:  tempDir,
	}

	if err := generator.Generate(); err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	tests := []struct {
		name          string
		file          string
		expectedPerms os.FileMode
	}{
		{
			name:          "CA private key",
			file:          "ca-test.local.key.pem",
			expectedPerms: 0600,
		},
		{
			name:          "CA certificate",
			file:          "ca-test.local.crt",
			expectedPerms: 0644,
		},
		{
			name:          "Wildcard private key",
			file:          "wildcard.test.local.key.pem",
			expectedPerms: 0600,
		},
		{
			name:          "Wildcard certificate",
			file:          "wildcard.test.local.crt",
			expectedPerms: 0644,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.file)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("failed to stat file: %v", err)
			}

			if info.Mode().Perm() != tt.expectedPerms {
				t.Errorf("incorrect file permissions for %s: got %v, want %v",
					tt.file, info.Mode().Perm(), tt.expectedPerms)
			}
		})
	}
}

// Benchmark certificate generation
func BenchmarkPKIGenerator_Generate(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "pki-bench-*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generator := &PKIGenerator{
			baseDomain: "test.local",
			outputDir:  filepath.Join(tempDir, "run", "test"),
		}
		if err := generator.Generate(); err != nil {
			b.Fatalf("failed to generate certificates: %v", err)
		}
		// Cleanup after each run
		os.RemoveAll(filepath.Join(tempDir, "run"))
	}
}

// Helper functions
func loadCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
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
