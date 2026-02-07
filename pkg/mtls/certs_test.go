package mtls

import (
	"bytes"
	"crypto/ed25519"
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

	if len(cert.Subject.StreetAddress) == 0 ||
		cert.Subject.StreetAddress[0] != config.StreetAddress {
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

	if block.Type != pemTypePrivateKey {
		t.Errorf("PEM block type should be '%s', got '%s'", pemTypePrivateKey, block.Type)
	}

	// Verify it can be parsed as a valid PKCS#8 private key
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key (PKCS#8): %v", err)
	}
	// Expect Ed25519 key by default
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("Expected Ed25519 private key, got %T", parsed)
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
	if cert.NotBefore.Before(beforeCall.Add(-time.Minute)) ||
		cert.NotBefore.After(afterCall.Add(time.Minute)) {
		t.Errorf("NotBefore not set correctly: %v", cert.NotBefore)
	}

	// NotAfter should be approximately 10 years from now (within 1 minute)
	expectedNotAfter := afterCall.AddDate(RootCAValidityYears, 0, 0)
	expectedNotAfterMin := beforeCall.AddDate(RootCAValidityYears, 0, 0)
	if cert.NotAfter.Before(expectedNotAfterMin.Add(-time.Minute)) ||
		cert.NotAfter.After(expectedNotAfter.Add(time.Minute)) {
		t.Errorf(
			"NotAfter not set correctly: %v (expected around %v)",
			cert.NotAfter,
			expectedNotAfter,
		)
	}
}

// TestCreateCSRCertificateSuccess tests successful CSR certificate creation
func TestCreateCSRCertificateSuccess(t *testing.T) {
	config := Config{
		Organization:  "Test Org",
		Country:       "US",
		Province:      "CA",
		Locality:      "San Francisco",
		StreetAddress: "123 Main St",
		PostalCode:    "94105",
		CommonName:    "test.example.com",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Verify all three components are present
	if len(csr.CSR) == 0 {
		t.Error("CSR is empty")
	}
	if len(csr.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}
	if len(csr.PublicKey) == 0 {
		t.Error("PublicKey is empty")
	}
}

// TestCreateCSRCertificateCSRFormat tests that CSR is in valid PEM format
func TestCreateCSRCertificateCSRFormat(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Verify CSR is PEM encoded
	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		t.Fatal("CSR is not valid PEM format")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("PEM block type should be 'CERTIFICATE REQUEST', got '%s'", block.Type)
	}

	// Verify it can be parsed as a valid X.509 certificate request
	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse CSR: %v", err)
	}

	// Verify the CSR subject matches config
	if len(csrParsed.Subject.Organization) == 0 || csrParsed.Subject.Organization[0] != config.Organization {
		t.Errorf("Organization mismatch in CSR")
	}
	if len(csrParsed.Subject.Country) == 0 || csrParsed.Subject.Country[0] != config.Country {
		t.Errorf("Country mismatch in CSR")
	}
}

// TestCreateCSRCertificatePrivateKeyFormat tests that private key is in valid PEM format
func TestCreateCSRCertificatePrivateKeyFormat(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Verify private key is PEM encoded
	block, _ := pem.Decode(csr.PrivateKey)
	if block == nil {
		t.Fatal("Private key is not valid PEM format")
	}

	if block.Type != pemTypePrivateKey {
		t.Errorf("PEM block type should be '%s', got '%s'", pemTypePrivateKey, block.Type)
	}

	// Verify it can be parsed as a valid PKCS#8 private key
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key (PKCS#8): %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("Expected Ed25519 private key, got %T", parsed)
	}
}

// TestCreateCSRCertificatePublicKeyFormat tests that public key is in valid PEM format
func TestCreateCSRCertificatePublicKeyFormat(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Verify public key is PEM encoded
	block, _ := pem.Decode(csr.PublicKey)
	if block == nil {
		t.Fatal("Public key is not valid PEM format")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM block type should be 'PUBLIC KEY', got '%s'", block.Type)
	}

	// Verify it can be parsed as a valid public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse public key: %v", err)
	}
}

// TestCreateCSRCertificateKeyPairConsistency tests that public and private keys are consistent
func TestCreateCSRCertificateKeyPairConsistency(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Parse private key (PKCS#8 for Ed25519)
	privKeyBlock, _ := pem.Decode(csr.PrivateKey)
	privKeyIntf, err := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
	privKey, ok := privKeyIntf.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected Ed25519 private key, got %T", privKeyIntf)
	}

	// Parse public key
	pubKeyBlock, _ := pem.Decode(csr.PublicKey)
	pubKeyIntf, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}
	pubKey, ok := pubKeyIntf.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key is not an Ed25519 public key")
	}

	// Verify they form a valid pair (compare derived public key from private)
	derivedPub := privKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, pubKey) {
		t.Error("Public key mismatch between private and public keys")
	}
}

// TestCreateCSRCertificateSubject tests that CSR subject is correct
func TestCreateCSRCertificateSubject(t *testing.T) {
	config := Config{
		Organization:  "Test Org Inc",
		Country:       "US",
		Province:      "California",
		Locality:      "San Francisco",
		StreetAddress: "456 Oak Ave",
		PostalCode:    "94102",
		CommonName:    "csr.example.com",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	// Parse CSR
	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		t.Fatalf("Failed to parse CSR PEM")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Verify subject fields
	if len(csrParsed.Subject.Organization) == 0 || csrParsed.Subject.Organization[0] != config.Organization {
		t.Errorf("Organization mismatch. Expected %s, got %v",
			config.Organization, csrParsed.Subject.Organization)
	}

	if len(csrParsed.Subject.Country) == 0 || csrParsed.Subject.Country[0] != config.Country {
		t.Errorf("Country mismatch. Expected %s, got %v",
			config.Country, csrParsed.Subject.Country)
	}

	if len(csrParsed.Subject.Province) == 0 || csrParsed.Subject.Province[0] != config.Province {
		t.Errorf("Province mismatch. Expected %s, got %v",
			config.Province, csrParsed.Subject.Province)
	}

	if len(csrParsed.Subject.Locality) == 0 || csrParsed.Subject.Locality[0] != config.Locality {
		t.Errorf("Locality mismatch. Expected %s, got %v",
			config.Locality, csrParsed.Subject.Locality)
	}

	if len(csrParsed.Subject.StreetAddress) == 0 ||
		csrParsed.Subject.StreetAddress[0] != config.StreetAddress {
		t.Errorf("StreetAddress mismatch. Expected %s, got %v",
			config.StreetAddress, csrParsed.Subject.StreetAddress)
	}

	if len(csrParsed.Subject.PostalCode) == 0 || csrParsed.Subject.PostalCode[0] != config.PostalCode {
		t.Errorf("PostalCode mismatch. Expected %s, got %v",
			config.PostalCode, csrParsed.Subject.PostalCode)
	}

	if csrParsed.Subject.CommonName != config.CommonName {
		t.Errorf("CommonName mismatch. Expected %s, got %s",
			config.CommonName, csrParsed.Subject.CommonName)
	}
}

// TestCreateCSRCertificateRandomKeyGeneration tests that each CSR has unique keys
func TestCreateCSRCertificateRandomKeyGeneration(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	// Generate multiple CSRs and collect their public keys
	publicKeys := make([]string, 5)
	for i := 0; i < 5; i++ {
		csr, err := CreateCSRCertificate(config)
		if err != nil {
			t.Fatalf("CreateCSRCertificate failed: %v", err)
		}

		// Parse public key
		block, _ := pem.Decode(csr.PublicKey)
		if block == nil {
			t.Fatalf("Failed to parse public key PEM")
		}

		publicKeys[i] = string(csr.PublicKey)
	}

	// Verify all public keys are unique
	uniqueKeys := make(map[string]bool)
	for _, key := range publicKeys {
		if uniqueKeys[key] {
			t.Error("Duplicate public key found across multiple CSR generations")
		}
		uniqueKeys[key] = true
	}

	if len(uniqueKeys) != 5 {
		t.Errorf("Expected 5 unique keys, got %d", len(uniqueKeys))
	}
}

// Helper function to verify PEM armor lines
func verifyPEMArmor(t *testing.T, pemData []byte, expectedType string) {
	pemStr := string(pemData)

	// Verify BEGIN line exists
	beginLine := "-----BEGIN " + expectedType + "-----"
	if !strings.Contains(pemStr, beginLine) {
		t.Errorf("Missing PEM BEGIN armor. Expected '%s' in:\n%s", beginLine, pemStr)
	}

	// Verify END line exists
	endLine := "-----END " + expectedType + "-----"
	if !strings.Contains(pemStr, endLine) {
		t.Errorf("Missing PEM END armor. Expected '%s' in:\n%s", endLine, pemStr)
	}

	// Verify BEGIN comes before END
	beginIdx := strings.Index(pemStr, beginLine)
	endIdx := strings.Index(pemStr, endLine)
	if beginIdx >= endIdx {
		t.Errorf("PEM BEGIN armor should come before END armor. BEGIN at %d, END at %d", beginIdx, endIdx)
	}

	// Verify data exists between BEGIN and END
	if endIdx-beginIdx <= len(beginLine)+len(endLine) {
		t.Error("PEM armor has no data between BEGIN and END lines")
	}
}

// TestRootCACertificatePEMArmor tests that CA certificate has proper PEM armor lines
func TestRootCACertificatePEMArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	verifyPEMArmor(t, ca.Certificate, "CERTIFICATE")
}

// TestRootCAPrivateKeyPEMArmor tests that CA private key has proper PEM armor lines
func TestRootCAPrivateKeyPEMArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	verifyPEMArmor(t, ca.PrivateKey, pemTypePrivateKey)
}

// TestCSRCertificateCSRPEMArmor tests that CSR has proper PEM armor lines
func TestCSRCertificateCSRPEMArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	verifyPEMArmor(t, csr.CSR, "CERTIFICATE REQUEST")
}

// TestCSRCertificatePrivateKeyPEMArmor tests that CSR private key has proper PEM armor lines
func TestCSRCertificatePrivateKeyPEMArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	verifyPEMArmor(t, csr.PrivateKey, pemTypePrivateKey)
}

// TestCSRCertificatePublicKeyPEMArmor tests that CSR public key has proper PEM armor lines
func TestCSRCertificatePublicKeyPEMArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	verifyPEMArmor(t, csr.PublicKey, "PUBLIC KEY")
}

// TestRootCACertificatePEMStartsWithArmor tests that certificate PEM starts with armor
func TestRootCACertificatePEMStartsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(ca.Certificate))
	expectedBegin := "-----BEGIN CERTIFICATE-----"

	if !strings.HasPrefix(pemStr, expectedBegin) {
		t.Errorf("Certificate PEM should start with '%s', got: %.50s...", expectedBegin, pemStr)
	}
}

// TestRootCACertificatePEMEndsWithArmor tests that certificate PEM ends with armor
func TestRootCACertificatePEMEndsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(ca.Certificate))
	expectedEnd := "-----END CERTIFICATE-----"

	if !strings.HasSuffix(pemStr, expectedEnd) {
		t.Errorf("Certificate PEM should end with '%s', got: ...%.50s", expectedEnd, pemStr)
	}
}

// TestRootCAPrivateKeyPEMStartsWithArmor tests that private key PEM starts with armor
func TestRootCAPrivateKeyPEMStartsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(ca.PrivateKey))
	expectedBegin := "-----BEGIN PRIVATE KEY-----"

	if !strings.HasPrefix(pemStr, expectedBegin) {
		t.Errorf("Private key PEM should start with '%s', got: %.50s...", expectedBegin, pemStr)
	}
}

// TestRootCAPrivateKeyPEMEndsWithArmor tests that private key PEM ends with armor
func TestRootCAPrivateKeyPEMEndsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(ca.PrivateKey))
	expectedEnd := "-----END PRIVATE KEY-----"

	if !strings.HasSuffix(pemStr, expectedEnd) {
		t.Errorf("Private key PEM should end with '%s', got: ...%.50s", expectedEnd, pemStr)
	}
}

// TestCSRCertificateCSRPEMStartsWithArmor tests that CSR PEM starts with armor
func TestCSRCertificateCSRPEMStartsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.CSR))
	expectedBegin := "-----BEGIN CERTIFICATE REQUEST-----"

	if !strings.HasPrefix(pemStr, expectedBegin) {
		t.Errorf("CSR PEM should start with '%s', got: %.50s...", expectedBegin, pemStr)
	}
}

// TestCSRCertificateCSRPEMEndsWithArmor tests that CSR PEM ends with armor
func TestCSRCertificateCSRPEMEndsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.CSR))
	expectedEnd := "-----END CERTIFICATE REQUEST-----"

	if !strings.HasSuffix(pemStr, expectedEnd) {
		t.Errorf("CSR PEM should end with '%s', got: ...%.50s", expectedEnd, pemStr)
	}
}

// TestCSRCertificatePrivateKeyPEMStartsWithArmor tests that CSR private key PEM starts with armor
func TestCSRCertificatePrivateKeyPEMStartsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.PrivateKey))
	expectedBegin := "-----BEGIN PRIVATE KEY-----"

	if !strings.HasPrefix(pemStr, expectedBegin) {
		t.Errorf("Private key PEM should start with '%s', got: %.50s...", expectedBegin, pemStr)
	}
}

// TestCSRCertificatePrivateKeyPEMEndsWithArmor tests that CSR private key PEM ends with armor
func TestCSRCertificatePrivateKeyPEMEndsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.PrivateKey))
	expectedEnd := "-----END PRIVATE KEY-----"

	if !strings.HasSuffix(pemStr, expectedEnd) {
		t.Errorf("Private key PEM should end with '%s', got: ...%.50s", expectedEnd, pemStr)
	}
}

// TestCSRCertificatePublicKeyPEMStartsWithArmor tests that CSR public key PEM starts with armor
func TestCSRCertificatePublicKeyPEMStartsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.PublicKey))
	expectedBegin := "-----BEGIN PUBLIC KEY-----"

	if !strings.HasPrefix(pemStr, expectedBegin) {
		t.Errorf("Public key PEM should start with '%s', got: %.50s...", expectedBegin, pemStr)
	}
}

// TestCSRCertificatePublicKeyPEMEndsWithArmor tests that CSR public key PEM ends with armor
func TestCSRCertificatePublicKeyPEMEndsWithArmor(t *testing.T) {
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}

	csr, err := CreateCSRCertificate(config)
	if err != nil {
		t.Fatalf("CreateCSRCertificate failed: %v", err)
	}

	pemStr := strings.TrimSpace(string(csr.PublicKey))
	expectedEnd := "-----END PUBLIC KEY-----"

	if !strings.HasSuffix(pemStr, expectedEnd) {
		t.Errorf("Public key PEM should end with '%s', got: ...%.50s", expectedEnd, pemStr)
	}
}

func TestLoadRootCA(t *testing.T) {
	// First, create a valid Root CA to get its PEM data
	config := Config{
		Organization: "Test Org",
		Country:      "US",
	}
	ca, err := CreateRootCA(config)
	if err != nil {
		t.Fatalf("CreateRootCA failed: %v", err)
	}

	// Now load the Root CA from the PEM data
	loadedCA, err := LoadRootCA(ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("LoadRootCA failed: %v", err)
	}

	// Verify loaded certificate matches original
	if !bytes.Equal(loadedCA.Certificate, ca.Certificate) {
		t.Error("Loaded certificate does not match original")
	}

	// Verify loaded private key matches original
	if !bytes.Equal(loadedCA.PrivateKey, ca.PrivateKey) {
		t.Error("Loaded private key does not match original")
	}
}
