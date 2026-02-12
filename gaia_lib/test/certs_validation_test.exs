defmodule GaiaLib.CertsValidationTest do
  use ExUnit.Case

  alias GaiaLib.Certs
  alias GaiaLib.Certs.CertConfig
  alias GaiaLib.CertsValidation

  describe "certificate_matches_private_key?/2" do
    test "returns true for matching PEM certificate and private key" do
      config = %CertConfig{organization: "Test Org", country: "US"}
      {:ok, ca} = Certs.create_root_ca(config)

      assert CertsValidation.certificate_matches_private_key?(ca.certificate, ca.private_key)
    end

    test "returns false for non-matching PEM private key" do
      config = %CertConfig{organization: "Test Org", country: "US"}
      {:ok, ca1} = Certs.create_root_ca(config)
      {:ok, ca2} = Certs.create_root_ca(config)

      refute CertsValidation.certificate_matches_private_key?(ca1.certificate, ca2.private_key)
    end

    test "works with OTP decoded cert and key structs" do
      config = %CertConfig{organization: "Test Org", country: "US"}
      {:ok, ca} = Certs.create_root_ca(config)

      {:ok, cert_struct} = X509.Certificate.from_pem(ca.certificate)
      {:ok, priv_struct} = X509.PrivateKey.from_pem(ca.private_key)

      assert CertsValidation.certificate_matches_private_key?(cert_struct, priv_struct)
    end

    test "works with DER binaries" do
      config = %CertConfig{organization: "Test Org", country: "US"}
      {:ok, ca} = Certs.create_root_ca(config)

      {:ok, cert_struct} = X509.Certificate.from_pem(ca.certificate)
      {:ok, priv_struct} = X509.PrivateKey.from_pem(ca.private_key)

      cert_der = X509.Certificate.to_der(cert_struct)
      priv_der = X509.PrivateKey.to_der(priv_struct)

      assert CertsValidation.certificate_matches_private_key?(cert_der, priv_der)

      # mismatch with different private key DER
      {:ok, ca2} = Certs.create_root_ca(config)
      {:ok, priv2} = X509.PrivateKey.from_pem(ca2.private_key)
      priv2_der = X509.PrivateKey.to_der(priv2)

      refute CertsValidation.certificate_matches_private_key?(cert_der, priv2_der)
    end

    test "returns false on invalid inputs" do
      refute CertsValidation.certificate_matches_private_key?("not a cert", "not a key")
    end
  end
end
