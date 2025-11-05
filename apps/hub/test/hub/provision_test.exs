defmodule Gaia.Hub.ProvisionTest do
  use ExUnit.Case

  setup_all do
    # Seed random for predictable tests
    :rand.seed(:exsplus, {123, 456, 789})
    :ok
  end

  test "generate_one_time_access_key returns a passphrase with 6 words" do
    key = Gaia.Hub.Provision.generate_one_time_access_key()
    assert is_binary(key)

    words = String.split(key, "-")
    assert length(words) == 6

    Enum.each(words, fn word ->
      assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
    end)
  end

  test "sign_certificate_request signs a valid CSR and returns a certificate" do
    # Generate test CA key and cert
    ca_key = X509.PrivateKey.new_rsa(2048)
    ca_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
    ca_cert = X509.Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

    # Generate client key and CSR
    client_key = X509.PrivateKey.new_rsa(2048)
    client_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")
    client_csr = X509.CSR.new(client_key, client_subject)

    # Write CA cert and key to temp files
    temp_dir = System.tmp_dir!()
    ca_cert_path = Path.join(temp_dir, "test_ca.pem")
    ca_key_path = Path.join(temp_dir, "test_ca.key")

    File.write!(ca_cert_path, X509.Certificate.to_pem(ca_cert))
    File.write!(ca_key_path, X509.PrivateKey.to_pem(ca_key))

    # Set application config for test
    original_config = Application.get_env(:hub, :cacert)
    Application.put_env(:hub, :cacert, cert: ca_cert_path, key: ca_key_path)

    try do
      # Call the function
      csr_pem = X509.CSR.to_pem(client_csr)
      result = Gaia.Hub.Provision.sign_certificate_request(csr_pem)

      # Assert it's a certificate
      cert =
        case result do
          {:ok, c} -> c
          c -> c
        end

      # :OTPCertificate is a tuple
      assert is_tuple(cert)

      # Verify the certificate was signed by our CA
      assert X509.RDNSequence.to_string(X509.Certificate.issuer(cert)) ==
               X509.RDNSequence.to_string(ca_subject)

      assert X509.RDNSequence.to_string(X509.Certificate.subject(cert)) ==
               X509.RDNSequence.to_string(client_subject)

      # Verify the public key matches
      client_public_key = X509.PublicKey.derive(client_key)
      assert X509.Certificate.public_key(cert) == client_public_key
    after
      # Restore original config
      if original_config do
        Application.put_env(:hub, :cacert, original_config)
      else
        Application.delete_env(:hub, :cacert)
      end

      # Clean up temp files
      File.rm(ca_cert_path)
      File.rm(ca_key_path)
    end
  end

  test "sign_certificate_request returns error for invalid CSR" do
    # Generate test CA key and cert
    ca_key = X509.PrivateKey.new_rsa(2048)
    ca_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
    ca_cert = X509.Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

    # Write CA cert and key to temp files
    temp_dir = System.tmp_dir!()
    ca_cert_path = Path.join(temp_dir, "test_ca_invalid.pem")
    ca_key_path = Path.join(temp_dir, "test_ca_invalid.key")

    File.write!(ca_cert_path, X509.Certificate.to_pem(ca_cert))
    File.write!(ca_key_path, X509.PrivateKey.to_pem(ca_key))

    # Set application config for test
    original_config = Application.get_env(:hub, :cacert)
    Application.put_env(:hub, :cacert, cert: ca_cert_path, key: ca_key_path)

    try do
      invalid_csr_pem = "invalid pem"
      result = Gaia.Hub.Provision.sign_certificate_request(invalid_csr_pem)
      assert {:error, _} = result
    after
      if original_config do
        Application.put_env(:hub, :cacert, original_config)
      else
        Application.delete_env(:hub, :cacert)
      end

      File.rm(ca_cert_path)
      File.rm(ca_key_path)
    end
  end
end
