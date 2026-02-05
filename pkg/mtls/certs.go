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

type CertificateAuthority struct {
	// Fields for the Certificate Authority
	PrivateKey  []byte
	Certificate []byte
}

type Config struct {
	StoragePath   string
	Organization  string
	Country       string
	Province      string
	Locality      string
	StreetAddress string
	PostalCode    string
}

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

// rsaKeySize defines the RSA key size for certificate generation
const rsaKeySize = 4096

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
	caPem := new(bytes.Buffer)
	if err := pem.Encode(caPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: failed to encode certificate to PEM: %w",
			err,
		)
	}

	// Encode private key to PEM format
	privateKeyPem := new(bytes.Buffer)
	if err := pem.Encode(privateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		return CertificateAuthority{}, fmt.Errorf(
			"CreateRootCA: failed to encode private key to PEM: %w",
			err,
		)
	}

	return CertificateAuthority{
		PrivateKey:  privateKeyPem.Bytes(),
		Certificate: caPem.Bytes(),
	}, nil
}

func buildCertificateInfo(config Config, serialNumber *big.Int) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{config.Organization},
			Country:       []string{config.Country},
			Province:      []string{config.Province},
			Locality:      []string{config.Locality},
			StreetAddress: []string{config.StreetAddress},
			PostalCode:    []string{config.PostalCode},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(RootCAValidityYears, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}
