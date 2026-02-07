package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PEM block type constants
const (
	pemTypeCertificate         = "CERTIFICATE"
	pemTypePrivateKey          = "PRIVATE KEY"
	pemTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	pemTypeECPrivateKey        = "EC PRIVATE KEY"
	pemTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemTypeCertRequest         = "CERTIFICATE REQUEST"
	pemTypePublicKey           = "PUBLIC KEY"
)

// RootCAValidityYears defines the validity period for Root CA certificates
const RootCAValidityYears = 10

// (previously RSA) key size removed — Ed25519 uses fixed-size keys

// CertificateOp represents the high-level operation being performed
// in certificate-related workflows. It is used to annotate errors
// and control flow so callers can determine which CA/CSR action
// caused an issue.
type CertificateOp int

const (
	// CertOpCreateRootCA indicates creating a new root Certificate
	// Authority (CA) including generating a keypair and self-signed cert.
	CertOpCreateRootCA CertificateOp = iota
	// CertOpLoadRootCA indicates loading an existing CA certificate
	// and private key from PEM-encoded input.
	CertOpLoadRootCA
	// CertOpCreateCSRCertificate indicates generating a CSR along with
	// a private/public keypair for a client or service certificate.
	CertOpCreateCSRCertificate
	// CertOpSignCSR indicates signing a PEM-encoded CSR with a CA to
	// produce a certificate issued by the CA.
	CertOpSignCSR
)

// CertificateError wraps errors that occur during certificate
// operations. `Message` is a human-readable description, `Err` is the
// underlying error being wrapped, and `Op` identifies which
// CertificateOp was active when the error occurred.
type CertificateError struct {
	Message string
	Err     error
	Op      CertificateOp
}

// Error implements the error interface for CertificateError. The
// returned string includes the human-readable Message and the wrapped
// underlying error, if present.
func (e CertificateError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap allows errors.Unwrap to retrieve the underlying error.
func (e CertificateError) Unwrap() error { return e.Err }

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
// CA Methods (Public)
// ============================================================================

// SignCSR signs a PEM-encoded CSR and returns a PEM-encoded certificate.
func (ca *CertificateAuthority) SignCSR(csrPem []byte, validityDays int) ([]byte, error) {
	// Parse the CA certificate
	caBlock, _ := pem.Decode(ca.Certificate)
	if caBlock == nil {
		return nil, CertificateError{Message: "SignCSR: failed to decode CA certificate", Op: CertOpSignCSR}
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, CertificateError{Message: "SignCSR: failed to parse CA certificate", Err: err, Op: CertOpSignCSR}
	}

	// Parse the CA private key
	caKey, err := decodeCAPrivateKey(ca.PrivateKey)
	if err != nil {
		return nil, CertificateError{Message: "SignCSR: failed to parse CA private key", Err: err, Op: CertOpSignCSR}
	}

	// Parse the CSR
	csrBlock, _ := pem.Decode(csrPem)
	if csrBlock == nil {
		return nil, CertificateError{Message: "SignCSR: failed to decode CSR", Op: CertOpSignCSR}
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, CertificateError{Message: "SignCSR: failed to parse CSR", Err: err, Op: CertOpSignCSR}
	}

	// Check CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, CertificateError{Message: "SignCSR: CSR signature check failed", Err: err, Op: CertOpSignCSR}
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, CertificateError{Message: "SignCSR: failed to generate serial number", Err: err, Op: CertOpSignCSR}
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, CertificateError{Message: "SignCSR: failed to sign certificate", Err: err, Op: CertOpSignCSR}
	}

	// Encode to PEM
	return encodePEM(pemTypeCertificate, certBytes)
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
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: configuration validation failed", Err: err, Op: CertOpCreateRootCA}
	}

	// Generate a random serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: failed to generate serial number", Err: err, Op: CertOpCreateRootCA}
	}

	ca := buildCertificateInfo(config, serialNumber)

	// Generate Ed25519 private key
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: failed to generate private key", Err: err, Op: CertOpCreateRootCA}
	}

	// Create the certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, privateKey)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: failed to generate certificate", Err: err, Op: CertOpCreateRootCA}
	}

	// Encode certificate to PEM format
	caPem, err := encodePEM(pemTypeCertificate, caBytes)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: failed to encode certificate to PEM", Err: err, Op: CertOpCreateRootCA}
	}

	// Encode private key to PEM format (use PKCS#8)
	privateKeyPem, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "CreateRootCA: failed to encode private key to PEM", Err: err, Op: CertOpCreateRootCA}
	}

	return CertificateAuthority{
		PrivateKey:  privateKeyPem,
		Certificate: caPem,
	}, nil
}

// LoadRootCA loads an existing root CA certificate and private key from PEM-encoded data.
// It assumes the provided PEM data is valid and properly formatted.
// This function is useful for loading a pre-generated CA from storage or configuration.
func LoadRootCA(caPem, keyPem []byte) (CertificateAuthority, error) {
	// Validate CA certificate
	ca, err := decodeCAPem(caPem)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "LoadRootCA: failed to decode CA certificate", Err: err, Op: CertOpLoadRootCA}
	}
	if !ca.IsCA {
		return CertificateAuthority{}, CertificateError{Message: "LoadRootCA: provided certificate is not a CA", Op: CertOpLoadRootCA}
	}
	// Validate CA private key
	privKey, err := decodeCAPrivateKey(keyPem)
	if err != nil {
		return CertificateAuthority{}, CertificateError{Message: "LoadRootCA: failed to parse CA private key", Err: err, Op: CertOpLoadRootCA}
	}
	// Ensure the private key matches the CA certificate's public key
	if err := verifyKeyMatchesCert(privKey, ca); err != nil {
		return CertificateAuthority{}, CertificateError{Message: "LoadRootCA: private key does not match certificate public key", Err: err, Op: CertOpLoadRootCA}
	}
	// Ensure the time validity of the CA certificate is still valid
	if time.Now().Before(ca.NotBefore) || time.Now().After(ca.NotAfter) {
		return CertificateAuthority{}, CertificateError{Message: "LoadRootCA: CA certificate is not currently valid", Op: CertOpLoadRootCA}
	}

	return CertificateAuthority{
		Certificate: caPem,
		PrivateKey:  keyPem,
	}, nil
}

// CreateCSRCertificate creates a certificate signing request (CSR) with associated
// private and public keys for use in certificate provisioning workflows.
func CreateCSRCertificate(config Config) (CSRCertificate, error) {
	csr := x509.CertificateRequest{
		Subject: config.toPKI(),
	}
	// generate Ed25519 key for CSR
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CSRCertificate{}, CertificateError{Message: "CreateCSRCertificate: error generating CSR private key", Err: err, Op: CertOpCreateCSRCertificate}
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
	if err != nil {
		return CSRCertificate{}, CertificateError{Message: "CreateCSRCertificate: error creating CSR", Err: err, Op: CertOpCreateCSRCertificate}
	}

	// Encode CSR to PEM format
	csrPem, err := encodePEM(pemTypeCertRequest, csrBytes)
	if err != nil {
		return CSRCertificate{}, CertificateError{Message: "CreateCSRCertificate: failed to encode CSR to PEM", Err: err, Op: CertOpCreateCSRCertificate}
	}

	// Encode private key to PEM format
	privateKeyPem, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return CSRCertificate{}, CertificateError{Message: "CreateCSRCertificate: failed to encode private key to PEM", Err: err, Op: CertOpCreateCSRCertificate}
	}

	// Encode public key to PEM format
	publicKeyPem, err := encodePublicKeyPEM(pub)
	if err != nil {
		return CSRCertificate{}, CertificateError{Message: "CreateCSRCertificate: failed to encode public key to PEM", Err: err, Op: CertOpCreateCSRCertificate}
	}

	return CSRCertificate{
		CSR:        csrPem,
		PrivateKey: privateKeyPem,
		PublicKey:  publicKeyPem,
	}, nil
}

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

// encodePrivateKeyPEM encodes a private key to PEM format using PKCS#8
func encodePrivateKeyPEM(privateKey interface{}) ([]byte, error) {
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	return encodePEM(pemTypePrivateKey, pkcs8Bytes)
}

// encodePublicKeyPEM encodes a public key (RSA, ECDSA, Ed25519, etc) to PEM format
func encodePublicKeyPEM(publicKey interface{}) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return encodePEM(pemTypePublicKey, publicKeyBytes)
}

func decodeCAPem(caPem []byte) (*x509.Certificate, error) {
	caBlock, _ := pem.Decode(caPem)
	if caBlock == nil {
		return &x509.Certificate{}, fmt.Errorf("failed to decode CA certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return &x509.Certificate{}, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return ca, nil
}

func decodeCAPrivateKey(keyPem []byte) (interface{}, error) {
	keyBlock, _ := pem.Decode(keyPem)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key")
	}

	// Reject encrypted PEM blocks (not supported). Avoid deprecated IsEncryptedPEMBlock.
	if keyBlock.Type == pemTypeEncryptedPrivateKey {
		return nil, fmt.Errorf("encrypted private keys are not supported")
	}

	switch keyBlock.Type {
	case pemTypeRSAPrivateKey:
		// legacy PKCS#1 RSA private key
		privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		return privKey, nil
	case pemTypePrivateKey:
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		return k, nil
	case pemTypeECPrivateKey:
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}
}

// verifyKeyMatchesCert checks the private key corresponds to the certificate's public key
func verifyKeyMatchesCert(key interface{}, cert *x509.Certificate) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("certificate public key is not RSA")
		}
		// rsa.PrivateKey embeds PublicKey; compare promoted fields directly.
		if k.N.Cmp(pub.N) != 0 || k.E != pub.E {
			return errors.New("rsa public key mismatch")
		}
		return nil
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("certificate public key is not ECDSA")
		}
		// ecdsa.PrivateKey embeds PublicKey; compare promoted fields directly.
		if k.X.Cmp(pub.X) != 0 || k.Y.Cmp(pub.Y) != 0 {
			return errors.New("ecdsa public key mismatch")
		}
		return nil
	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("certificate public key is not Ed25519")
		}
		if !bytes.Equal(k.Public().(ed25519.PublicKey), pub) {
			return errors.New("ed25519 public key mismatch")
		}
		return nil
	default:
		return errors.New("unsupported private key type")
	}
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
