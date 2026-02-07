package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestLoadRootCA_PKCS8(t *testing.T) {
	rsaKeySize = 2048
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}
	if _, err := LoadRootCA(ca.Certificate, ca.PrivateKey); err != nil {
		t.Fatalf("LoadRootCA failed for PKCS#8 key: %v", err)
	}
}

func TestLoadRootCA_PKCS1(t *testing.T) {
	rsaKeySize = 2048
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}

	// decode PKCS#8 and re-encode as PKCS#1
	block, _ := pem.Decode(ca.PrivateKey)
	if block == nil {
		t.Fatalf("failed to decode created CA private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key from PKCS#8")
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	if _, err := LoadRootCA(ca.Certificate, pkcs1); err != nil {
		t.Fatalf("LoadRootCA failed for PKCS#1 key: %v", err)
	}
}

func TestLoadRootCA_EC(t *testing.T) {
	cfg := Config{Organization: "TestOrg", Country: "US"}
	// generate ECDSA key and self-signed CA cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := buildCertificateInfo(cfg, serial)
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate EC: %v", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPem, err := encodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("encodePrivateKeyPEM EC: %v", err)
	}
	if _, err := LoadRootCA(certPem, keyPem); err != nil {
		t.Fatalf("LoadRootCA failed for EC key: %v", err)
	}
}

func TestLoadRootCA_MismatchedKey(t *testing.T) {
	rsaKeySize = 2048
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}
	// generate a different key
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherPem, err := encodePrivateKeyPEM(otherKey)
	if err != nil {
		t.Fatalf("encode other key: %v", err)
	}
	if _, err := LoadRootCA(ca.Certificate, otherPem); err == nil {
		t.Fatalf("expected LoadRootCA to fail for mismatched key, but it succeeded")
	}
}

func TestLoadRootCA_EncryptedKeyRejected(t *testing.T) {
	rsaKeySize = 2048
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}
	// simulate an encrypted PEM by labeling the block type (we don't use legacy PEM encryption)
	block, _ := pem.Decode(ca.PrivateKey)
	if block == nil {
		t.Fatalf("failed to decode created CA private key PEM")
	}
	encryptedBlock := &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: block.Bytes}
	encryptedPem := pem.EncodeToMemory(encryptedBlock)
	if _, err := LoadRootCA(ca.Certificate, encryptedPem); err == nil {
		t.Fatalf("expected LoadRootCA to reject encrypted key, but it succeeded")
	}
}
