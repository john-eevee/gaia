package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestCreateRootCASuccess tests successful Root CA creation with valid config
func TestCreateRootCASuccess(t *testing.T) {
	config := Config{
		Organization:  "Test Org",
		Country:       "US",
		Province:      "CA",
		Locality:      "San Francisco",
		StreetAddress: "123 Main St",
		PostalCode:    "94105",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Verify both private key and certificate are present
	if len(ca.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}
	if len(ca.Certificate) == 0 {
		t.Error("Certificate is empty")
	}
}

// TestCreateRootCAMissingOrganization tests Config validation for missing Organization
func TestCreateRootCAMissingOrganization(t *testing.T) {
	config := Config{
		Country: "US",
		// Organization is intentionally missing
	}

	_, err := CreateRootCA(config)
	if err == nil {
		t.Error("Expected error for missing Organization, got nil")
	}

	// Verify error contains validation message
	if !strings.Contains(err.Error(), "Organization is required") {
		t.Errorf("Expected 'Organization is required' in error, got: %v", err)
	}
}

// TestCreateRootCAMissingCountry tests Config validation for missing Country
func TestCreateRootCAMissingCountry(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		// Country is intentionally missing
	}

	_, err := CreateRootCA(config)
	if err == nil {
		t.Error("Expected error for missing Country, got nil")
	}

	// Verify error contains validation message
	if !strings.Contains(err.Error(), "Country is required") {
		t.Errorf("Expected 'Country is required' in error, got: %v", err)
	}
}

// TestCreateRootCARandomSerialNumbers tests that serial numbers are unique
func TestCreateRootCARandomSerialNumbers(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	// Generate multiple CAs and collect serial numbers
	serialNumbers := make(map[string]bool)
	for i := 0; i < 5; i++ {
		ca, err := CreateRootCA(config)
		if err != nil {
			t.Fatalf("CreateRootCA failed: %v", err)
		}

		// Extract certificate to get serial number
		block, _ := pem.Decode(ca.Certificate)
		if block == nil {
			t.Fatalf("Failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		serialStr := cert.SerialNumber.String()
		if serialNumbers[serialStr] {
			t.Errorf("Duplicate serial number found: %s", serialStr)
		}
		serialNumbers[serialStr] = true
	}

	// Verify we have 5 unique serial numbers
	if len(serialNumbers) != 5 {
		t.Errorf("Expected 5 unique serial numbers, got %d", len(serialNumbers))
	}
}

// TestCreateRootCACertificateValidity tests that certificate validity is correct
func TestCreateRootCACertificateValidity(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatalf("Failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Check NotBefore is approximately now (within 1 minute)
	now := time.Now().UTC()
	if cert.NotBefore.After(now.Add(time.Minute)) || cert.NotBefore.Before(now.Add(-time.Minute)) {
		t.Errorf("NotBefore not set correctly: %v vs %v", cert.NotBefore, now)
	}

	// Check NotAfter is approximately 10 years from now (within 1 minute)
	expectedNotAfter := now.AddDate(RootCAValidityYears, 0, 0)
	if cert.NotAfter.Before(expectedNotAfter.Add(-time.Minute)) ||
		cert.NotAfter.After(expectedNotAfter.Add(time.Minute)) {
		t.Errorf("NotAfter not set correctly for %d years: %v vs %v",
			RootCAValidityYears, cert.NotAfter, expectedNotAfter)
	}
}

// TestCreateRootCACertificateIsCA tests that certificate is marked as CA
func TestCreateRootCACertificateIsCA(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatalf("Failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify IsCA is true
	if !cert.IsCA {
		t.Error("Certificate IsCA flag should be true")
	}

	// Verify BasicConstraintsValid is true
	if !cert.BasicConstraintsValid {
		t.Error("Certificate BasicConstraintsValid should be true")
	}
}

// TestCreateRootCACertificateKeyUsage tests that key usage is correct for mTLS
func TestCreateRootCACertificateKeyUsage(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatalf("Failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify KeyUsage contains DigitalSignature and CertSign
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if cert.KeyUsage != expectedKeyUsage {
		t.Errorf("KeyUsage mismatch. Expected %d, got %d", expectedKeyUsage, cert.KeyUsage)
	}

	// Verify ExtKeyUsage contains ServerAuth and ClientAuth (for mTLS)
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("ExtKeyUsage should contain ExtKeyUsageServerAuth")
	}
	if !hasClientAuth {
		t.Error("ExtKeyUsage should contain ExtKeyUsageClientAuth")
	}

	// Verify it does NOT have CodeSigning (this was the bug)
	hasCodeSigning := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
		}
	}
	if hasCodeSigning {
		t.Error("ExtKeyUsage should NOT contain ExtKeyUsageCodeSigning for mTLS")
	}
}

// TestCreateRootCACertificateSubject tests that certificate subject is correct
func TestCreateRootCACertificateSubject(t *testing.T) {
	config := Config{
		Organization:  "Test Org Inc",
		Country:       "US",
		Province:      "California",
		Locality:      "San Francisco",
		StreetAddress: "456 Oak Ave",
		PostalCode:    "94102",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatalf("Failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify subject fields
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != config.Organization {
		t.Errorf("Organization mismatch. Expected %s, got %v",
			config.Organization, cert.Subject.Organization)
	}

	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != config.Country {
		t.Errorf("Country mismatch. Expected %s, got %v",
			config.Country, cert.Subject.Country)
	}

	if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != config.Province {
		t.Errorf("Province mismatch. Expected %s, got %v",
			config.Province, cert.Subject.Province)
	}

	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != config.Locality {
		t.Errorf("Locality mismatch. Expected %s, got %v",
			config.Locality, cert.Subject.Locality)
	}

	if len(cert.Subject.StreetAddress) == 0 || cert.Subject.StreetAddress[0] != config.StreetAddress {
		t.Errorf("StreetAddress mismatch. Expected %s, got %v",
			config.StreetAddress, cert.Subject.StreetAddress)
	}

	if len(cert.Subject.PostalCode) == 0 || cert.Subject.PostalCode[0] != config.PostalCode {
		t.Errorf("PostalCode mismatch. Expected %s, got %v",
			config.PostalCode, cert.Subject.PostalCode)
	}
}

// TestCreateRootCACertificatePEMFormat tests that certificate is in valid PEM format
func TestCreateRootCACertificatePEMFormat(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Verify certificate is PEM encoded
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatal("Certificate is not valid PEM format")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type should be 'CERTIFICATE', got '%s'", block.Type)
	}

	// Verify it can be parsed as a valid X.509 certificate
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse certificate: %v", err)
	}
}

// TestCreateRootCAPrivateKeyPEMFormat tests that private key is in valid PEM format
func TestCreateRootCAPrivateKeyPEMFormat(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Verify private key is PEM encoded
	block, _ := pem.Decode(ca.PrivateKey)
	if block == nil {
		t.Fatal("Private key is not valid PEM format")
	}

	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("PEM block type should be 'RSA PRIVATE KEY', got '%s'", block.Type)
	}

	// Verify it can be parsed as a valid RSA private key
	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %v", err)
	}
}

// TestCreateRootCASelfSigned tests that the certificate is self-signed
func TestCreateRootCASelfSigned(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(ca.Certificate)
	if block == nil {
		t.Fatalf("Failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// For a self-signed certificate, Issuer should equal Subject
	if cert.Issuer.String() != cert.Subject.String() {
		t.Error("Certificate should be self-signed (Issuer should equal Subject)")
	}

	// Verify it can verify itself
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}
}

// TestConfigValidateSuccess tests successful Config validation
func TestConfigValidateSuccess(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validation should succeed for valid config, got error: %v", err)
	}
}

// TestConfigValidateEmptyOrganization tests Config validation with empty Organization
func TestConfigValidateEmptyOrganization(t *testing.T) {
	config := Config{
		Organization: "",
		Country:      "US",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validation should fail for empty Organization")
	}

	if !strings.Contains(err.Error(), "Organization is required") {
		t.Errorf("Expected 'Organization is required' in error, got: %v", err)
	}
}

// TestConfigValidateEmptyCountry tests Config validation with empty Country
func TestConfigValidateEmptyCountry(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validation should fail for empty Country")
	}

	if !strings.Contains(err.Error(), "Country is required") {
		t.Errorf("Expected 'Country is required' in error, got: %v", err)
	}
}

// TestConfigValidateOptionalFields tests that optional fields are not required
func TestConfigValidateOptionalFields(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
		// All other fields are omitted
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validation should succeed with only required fields, got error: %v", err)
	}
}

// TestBuildCertificateInfoSerialNumber tests buildCertificateInfo uses provided serial number
func TestBuildCertificateInfoSerialNumber(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	serialNumber := big.NewInt(12345)
	cert := buildCertificateInfo(config, serialNumber)

	if cert.SerialNumber.Cmp(serialNumber) != 0 {
		t.Errorf("Serial number mismatch. Expected %v, got %v", serialNumber, cert.SerialNumber)
	}
}

// TestBuildCertificateInfoValidity tests buildCertificateInfo sets correct validity
func TestBuildCertificateInfoValidity(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	beforeCall := time.Now().UTC()
	cert := buildCertificateInfo(config, big.NewInt(1))
	afterCall := time.Now().UTC()

	// NotBefore should be approximately now (within 1 minute)
	if cert.NotBefore.Before(beforeCall.Add(-time.Minute)) || cert.NotBefore.After(afterCall.Add(time.Minute)) {
		t.Errorf("NotBefore not set correctly: %v", cert.NotBefore)
	}

	// NotAfter should be approximately 10 years from now (within 1 minute)
	expectedNotAfter := afterCall.AddDate(RootCAValidityYears, 0, 0)
	expectedNotAfterMin := beforeCall.AddDate(RootCAValidityYears, 0, 0)
	if cert.NotAfter.Before(expectedNotAfterMin.Add(-time.Minute)) || cert.NotAfter.After(expectedNotAfter.Add(time.Minute)) {
		t.Errorf("NotAfter not set correctly: %v (expected around %v)", cert.NotAfter, expectedNotAfter)
	}
}

// Benchmark test for certificate generation
func BenchmarkCreateRootCA(b *testing.B) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateRootCA(config)
	}
}
