package mtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestLoadRootCA_PKCS8(t *testing.T) {
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}
	if _, err := LoadRootCA(ca.Certificate, ca.PrivateKey); err != nil {
		t.Fatalf("LoadRootCA failed for PKCS#8 key: %v", err)
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
	certPem := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: certBytes})
	keyPem, err := encodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("encodePrivateKeyPEM EC: %v", err)
	}
	if _, err := LoadRootCA(certPem, keyPem); err != nil {
		t.Fatalf("LoadRootCA failed for EC key: %v", err)
	}
}

func TestLoadRootCA_MismatchedKey(t *testing.T) {
	cfg := Config{Organization: "TestOrg", Country: "US"}
	ca, err := CreateRootCA(cfg)
	if err != nil {
		t.Fatalf("CreateRootCA error: %v", err)
	}
	// generate a different key
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
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
	encryptedBlock := &pem.Block{Type: pemTypeEncryptedPrivateKey, Bytes: block.Bytes}
	encryptedPem := pem.EncodeToMemory(encryptedBlock)
	if _, err := LoadRootCA(ca.Certificate, encryptedPem); err == nil {
		t.Fatalf("expected LoadRootCA to reject encrypted key, but it succeeded")
	}
}
