package mtls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// RootCAValidityYears defines the validity period for Root CA certificates
const RootCAValidityYears = 10

// rsaKeySize defines the RSA key size for certificate generation
const rsaKeySize = 4096

// CertificateAuthority represents a root certificate authority (CA) with its private key and certificate.
type CertificateAuthority struct {
	PrivateKey  []byte
	Certificate []byte
}

// Config contains the configuration for certificate generation including
// organization details and certificate subject information.
type Config struct {
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	StreetAddress      string
	PostalCode         string
	CommonName         string
}

// CSRCertificate represents a certificate signing request with its associated keys.
type CSRCertificate struct {
	CSR        []byte
	PrivateKey []byte
	PublicKey  []byte
}

// ============================================================================
// Config Methods (Public)
// ============================================================================

// Validate checks that the Config has required fields set
func (c *Config) Validate() error {
	if c.Organization == "" {
		return fmt.Errorf("Config validation failed: Organization is required")
	}
	if c.Country == "" {
		return fmt.Errorf("Config validation failed: Country is required")
	}
	return nil
}

// CreateRootCA creates a root certificate authority (CA) for mTLS.
// This CA can be used to sign client signing requests (CSRs) and issue
// certificates for secure communication between services.
func CreateRootCA(config Config) (CertificateAuthority, error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return CertificateAuthority{}, fmt.Errorf("CreateRootCA: %w", err)
	}

	// Generate a random serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: failed to generate serial number: %w",
			err,
		)
	}

	ca := buildCertificateInfo(config, serialNumber)

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: failed to generate private key: %w",
			err,
		)
	}

	// Create the certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: failed to generate certificate: %w",
			err,
		)
	}

	// Encode certificate to PEM format
	caPem, err := encodePEM("CERTIFICATE", caBytes)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: %w", err,
		)
	}

	// Encode private key to PEM format
	privateKeyPem, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: %w", err,
		)
	}

	return CertificateAuthority{
		PrivateKey:  privateKeyPem,
		Certificate: caPem,
	}, nil
}

// CreateCSRCertificate creates a certificate signing request (CSR) with associated
// private and public keys for use in certificate provisioning workflows.
func CreateCSRCertificate(config Config) (CSRCertificate, error) {
	csr := x509.CertificateRequest{
		Subject: config.toPKI(),
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return CSRCertificate{}, fmt.Errorf(
			"CreateCSRCertificate: error generating CSR private key: %w",
			err,
		)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
	if err != nil {
		return CSRCertificate{}, fmt.Errorf(
			"CreateCSRCertificate: error creating CSR: %w",
			err,
		)
	}

	// Encode CSR to PEM format
	csrPem, err := encodePEM("CERTIFICATE REQUEST", csrBytes)
	if err != nil {
		return CSRCertificate{}, fmt.Errorf(
			"CreateCSRCertificate: %w", err,
		)
	}

	// Encode private key to PEM format
	privateKeyPem, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return CSRCertificate{}, fmt.Errorf(
			"CreateCSRCertificate: %w", err,
		)
	}

	// Encode public key to PEM format
	publicKeyPem, err := encodePublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		return CSRCertificate{}, fmt.Errorf(
			"CreateCSRCertificate: %w", err,
		)
	}

	return CSRCertificate{
		CSR:        csrPem,
		PrivateKey: privateKeyPem,
		PublicKey:  publicKeyPem,
	}, nil
}

// ============================================================================
// Private Helper Functions
// ============================================================================

// toPKI converts a Config to a pkix.Name for use in certificate subject fields
func (config Config) toPKI() pkix.Name {
	return pkix.Name{
		Organization:       []string{config.Organization},
		OrganizationalUnit: []string{config.OrganizationalUnit},
		Country:            []string{config.Country},
		Province:           []string{config.Province},
		Locality:           []string{config.Locality},
		StreetAddress:      []string{config.StreetAddress},
		PostalCode:         []string{config.PostalCode},
		CommonName:         config.CommonName,
	}
}

// encodePEM encodes bytes into PEM format with the given PEM type
func encodePEM(pemType string, data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  pemType,
		Bytes: data,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode %s to PEM: %w", pemType, err)
	}
	return buf.Bytes(), nil
}

// encodePrivateKeyPEM encodes an RSA private key to PEM format
func encodePrivateKeyPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	return encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))
}

// encodePublicKeyPEM encodes an RSA public key to PEM format
func encodePublicKeyPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return encodePEM("PUBLIC KEY", publicKeyBytes)
}

// buildCertificateInfo constructs a certificate with the given config and serial number
func buildCertificateInfo(config Config, serialNumber *big.Int) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      config.toPKI(),
		NotBefore:    now,
		NotAfter:     now.AddDate(RootCAValidityYears, 0, 0),
		IsCA:         true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}
