defmodule Gaia.FarmNode.HubConnection.Provisioning.CertificateAuthorityTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.HubConnection.Provisioning.CertificateAuthority

  describe "generate_csr/1" do
    test "generates a valid CSR and private key" do
      farm_id = "test-farm-#{System.unique_integer([:positive])}"

      assert {:ok, %{csr: csr, private_key: private_key}} =
               CertificateAuthority.generate_csr(farm_id)

      # Verify private key is PEM encoded
      assert String.contains?(private_key, "BEGIN RSA PRIVATE KEY")
      assert String.contains?(private_key, "END RSA PRIVATE KEY")

      # Verify CSR is PEM encoded
      assert String.contains?(csr, "BEGIN CERTIFICATE REQUEST")
      assert String.contains?(csr, "END CERTIFICATE REQUEST")
    end

    test "generates different keys for different calls" do
      {:ok, %{private_key: key1}} = CertificateAuthority.generate_csr("farm-1")
      {:ok, %{private_key: key2}} = CertificateAuthority.generate_csr("farm-2")

      # Keys should be unique
      assert key1 != key2
    end

    test "CSR can be decoded" do
      {:ok, %{csr: csr}} = CertificateAuthority.generate_csr("test-farm")

      # Should be able to decode the PEM without errors
      assert [{:CertificationRequest, _der, :not_encrypted}] =
               :public_key.pem_decode(csr)
    end
  end

  describe "validate_certificate/1" do
    test "accepts a valid certificate PEM" do
      # Generate a self-signed certificate for testing
      cert_pem = generate_test_certificate()

      assert :ok = CertificateAuthority.validate_certificate(cert_pem)
    end

    test "rejects invalid PEM format" do
      invalid_pem = "not a valid pem"

      assert {:error, _} = CertificateAuthority.validate_certificate(invalid_pem)
    end

    test "rejects non-certificate PEM" do
      # Generate a private key (not a certificate)
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, private_key)
      pem_string = :public_key.pem_encode([pem_entry])

      assert {:error, :invalid_certificate_format} =
               CertificateAuthority.validate_certificate(pem_string)
    end
  end

  # Helper to generate a test certificate
  defp generate_test_certificate do
    # Generate a key pair
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    # Create a self-signed certificate using X509
    subject = X509.RDNSequence.new("/CN=test-farm/O=Test Org/C=US")

    # Create certificate
    cert =
      X509.Certificate.self_signed(
        private_key,
        subject,
        template: :server
      )

    # Encode to PEM
    X509.Certificate.to_pem(cert)
  end
end
