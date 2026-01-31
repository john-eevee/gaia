defmodule Gaia.FarmNode.HubConnection.Provisioning.PemParseTest do
  use ExUnit.Case, async: true

  test "generated X509 certificate decodes and pkix_decode_cert returns OTP style tuple" do
    # Create a self-signed certificate using public_key / X509 so we know the DER
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    subject = X509.RDNSequence.new("/CN=test-parse/O=Test/C=US")
    cert = X509.Certificate.self_signed(private_key, subject)
    pem = X509.Certificate.to_pem(cert)

    # Ensure we can decode the PEM and get a Certificate entry
    entries = :public_key.pem_decode(pem)
    assert [{:Certificate, der, _} | _] = entries

    # Ensure pkix decode returns an OTP certificate tuple
    otp_cert = :public_key.pkix_decode_cert(der, :otp)
    assert is_tuple(otp_cert)

    # Ensure subject and validity can be extracted without raising
    {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, subject, _, _, _, _, _}, _, _} = otp_cert
    assert is_tuple(subject)
  end
end
