package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCertificateAuthority_SignCSR(t *testing.T) {
	caConfig := Config{
		Organization: "Test CA",
		Country:      "US",
	}
	ca, err := CreateRootCA(caConfig)
	if err != nil {
		t.Fatalf("Failed to create Root CA: %v", err)
	}

	nodeConfig := Config{
		Organization: "Test Node",
		Country:      "US",
		CommonName:   "node-001",
	}
	csrInfo, err := CreateCSRCertificate(nodeConfig)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	validityDays := 365
	certPem, err := ca.SignCSR(csrInfo.CSR, validityDays)
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify the signed certificate
	block, _ := pem.Decode(certPem)
	if block == nil {
		t.Fatal("Failed to decode signed certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed certificate: %v", err)
	}

	if cert.Subject.CommonName != nodeConfig.CommonName {
		t.Errorf("Subject CommonName mismatch. Expected %s, got %s", nodeConfig.CommonName, cert.Subject.CommonName)
	}

	// Verify it's signed by the CA
	caBlock, _ := pem.Decode(ca.Certificate)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}

	// Verify key usage
	if cert.IsCA {
		t.Error("Issued certificate should not be a CA")
	}

	foundClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
			break
		}
	}
	if !foundClientAuth {
		t.Error("Issued certificate missing ClientAuth extension")
	}
}
