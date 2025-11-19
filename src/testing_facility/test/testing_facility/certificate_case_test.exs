defmodule Gaia.TestingFacility.CertificateCaseTest do
  use ExUnit.Case, async: false

  alias Gaia.TestingFacility.CertificateCase
  alias X509.Certificate
  alias X509.RDNSequence

  @default_client_subject RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")

  test "create_ca_certificate returns CA key, cert, and subject" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    assert ca_key != nil
    assert ca_cert != nil
    assert RDNSequence.to_string(ca_subject) == "/C=US/ST=CA/O=Test CA/CN=Test CA"

    assert RDNSequence.to_string(Certificate.subject(ca_cert)) ==
             RDNSequence.to_string(ca_subject)
  end

  test "create_signed_client_certificate produces PEM, serial, and public key" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, pem, serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    assert cert != nil
    assert String.contains?(pem, "-----BEGIN CERTIFICATE-----")
    assert serial =~ ~r/^[0-9A-F]+$/

    assert RDNSequence.to_string(Certificate.subject(cert)) ==
             RDNSequence.to_string(@default_client_subject)

    assert RDNSequence.to_string(Certificate.issuer(cert)) ==
             RDNSequence.to_string(ca_subject)
  end

  test "verify_signed_certificate returns ok with certificate" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, _pem, _serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    expected_public_key = Certificate.public_key(cert)

    assert {:ok, ^cert} =
             CertificateCase.verify_signed_certificate(
               {:ok, cert},
               @default_client_subject,
               ca_subject,
               expected_public_key
             )
  end

  test "verify_signed_certificate passes through errors" do
    assert {:error, :some_issue} =
             CertificateCase.verify_signed_certificate(
               {:error, :some_issue},
               nil,
               nil,
               nil
             )
  end

  test "setup_full_test_environment writes files and configures provision" do
    original_config = Application.get_env(:hub, :provision)
    context = CertificateCase.setup_full_test_environment()

    cleanup = fn -> CertificateCase.cleanup_test_environment(context) end
    on_exit(cleanup)

    assert File.exists?(context.ca_cert_path)
    assert File.exists?(context.ca_key_path)
    assert Application.get_env(:hub, :provision) == context.test_provision_config

    assert context.test_provision_config[:passphrase_word_count] == 6
    assert context.test_provision_config[:key_validity_days] == 365

    cleanup.()
    assert Application.get_env(:hub, :provision) == original_config
  end

  test "cleanup_test_environment restores env and removes files" do
    original_config = Application.get_env(:hub, :provision)
    temp_dir = System.tmp_dir!()

    temp_file =
      Path.join(temp_dir, "certificate_case_cleanup_#{:erlang.unique_integer([:positive])}")

    File.write!(temp_file, "cleanup")
    Application.put_env(:hub, :provision, [:dummy])

    context = %{
      original_provision_config: original_config,
      temp_files: [temp_file]
    }

    assert :ok == CertificateCase.cleanup_test_environment(context)
    refute File.exists?(temp_file)
    assert Application.get_env(:hub, :provision) == original_config
  end

  test "create_test_csr with default subject" do
    result = CertificateCase.create_test_csr()

    assert result.client_key != nil
    assert result.client_subject != nil
    assert result.client_csr != nil
    assert String.contains?(result.client_csr_pem, "-----BEGIN CERTIFICATE REQUEST-----")

    assert RDNSequence.to_string(result.client_subject) ==
             "/C=US/ST=CA/O=Test/CN=test.example.com"
  end

  test "create_test_csr with custom subject" do
    custom_subject = RDNSequence.new("/C=UK/ST=London/O=Custom/CN=custom.example.com")
    result = CertificateCase.create_test_csr(custom_subject)

    assert result.client_key != nil
    assert result.client_csr != nil
    assert String.contains?(result.client_csr_pem, "-----BEGIN CERTIFICATE REQUEST-----")

    assert RDNSequence.to_string(result.client_subject) ==
             "/C=UK/ST=London/O=Custom/CN=custom.example.com"
  end

  test "verify_signed_certificate with PEM string" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, pem, _serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    expected_public_key = Certificate.public_key(cert)

    assert {:ok, ^cert} =
             CertificateCase.verify_signed_certificate(
               {:ok, pem},
               @default_client_subject,
               ca_subject,
               expected_public_key
             )
  end

  test "verify_signed_certificate fails with wrong subject" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, _pem, _serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    wrong_subject = RDNSequence.new("/C=US/ST=CA/O=Wrong/CN=wrong.example.com")
    expected_public_key = Certificate.public_key(cert)

    assert {:error, _msg} =
             CertificateCase.verify_signed_certificate(
               {:ok, cert},
               wrong_subject,
               ca_subject,
               expected_public_key
             )
  end

  test "verify_signed_certificate fails with wrong issuer" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, _pem, _serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    wrong_ca_subject = RDNSequence.new("/C=US/ST=CA/O=Wrong CA/CN=Wrong CA")
    expected_public_key = Certificate.public_key(cert)

    assert {:error, _msg} =
             CertificateCase.verify_signed_certificate(
               {:ok, cert},
               @default_client_subject,
               wrong_ca_subject,
               expected_public_key
             )
  end

  test "verify_signed_certificate fails with wrong public key" do
    {ca_key, ca_cert, ca_subject} = CertificateCase.create_ca_certificate()

    {cert, _pem, _serial} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    # Create another cert to get a different public key
    {wrong_cert, _, _} =
      CertificateCase.create_signed_client_certificate({ca_key, ca_cert, ca_subject})

    wrong_public_key = Certificate.public_key(wrong_cert)

    assert {:error, _msg} =
             CertificateCase.verify_signed_certificate(
               {:ok, cert},
               @default_client_subject,
               ca_subject,
               wrong_public_key
             )
  end

  test "create_signed_client_certificate with default CA" do
    {cert, pem, serial} = CertificateCase.create_signed_client_certificate()

    assert cert != nil
    assert String.contains?(pem, "-----BEGIN CERTIFICATE-----")
    assert serial =~ ~r/^[0-9A-F]+$/

    assert RDNSequence.to_string(Certificate.subject(cert)) ==
             RDNSequence.to_string(@default_client_subject)
  end

  test "cleanup_test_environment without original_provision_config" do
    temp_dir = System.tmp_dir!()
    temp_file = Path.join(temp_dir, "cleanup_no_config_#{:erlang.unique_integer([:positive])}")
    File.write!(temp_file, "test")

    context = %{temp_files: [temp_file]}

    assert :ok == CertificateCase.cleanup_test_environment(context)
    refute File.exists?(temp_file)
    # Since no original, it should delete the env
    assert Application.get_env(:hub, :provision) == nil
  end

  test "cleanup_test_environment without temp_files" do
    original_config = Application.get_env(:hub, :provision)
    Application.put_env(:hub, :provision, [:test])

    context = %{original_provision_config: original_config}

    assert :ok == CertificateCase.cleanup_test_environment(context)
    assert Application.get_env(:hub, :provision) == original_config
  end

  test "setup_test_ca creates temporary files and context" do
    context = CertificateCase.setup_test_ca()

    assert context.ca_key != nil
    assert context.ca_cert != nil
    assert context.ca_subject != nil
    assert File.exists?(context.ca_cert_path)
    assert File.exists?(context.ca_key_path)
    assert context.temp_files == [context.ca_cert_path, context.ca_key_path]

    # Cleanup
    CertificateCase.cleanup_test_environment(context)
  end

  test "setup_provision_config sets application env" do
    context = %{ca_cert_path: "/fake/cert", ca_key_path: "/fake/key"}
    original = Application.get_env(:hub, :provision)

    updated_context = CertificateCase.setup_provision_config(context)

    assert Application.get_env(:hub, :provision) == updated_context.test_provision_config
    assert updated_context.original_provision_config == original
    assert updated_context.test_provision_config[:cacert][:cert] == "/fake/cert"
    assert updated_context.test_provision_config[:passphrase_word_count] == 6

    # Restore
    Application.put_env(:hub, :provision, original)
  end

  test "verify_signed_certificate with invalid PEM" do
    assert {:error, _reason} =
             CertificateCase.verify_signed_certificate(
               {:ok, "invalid pem"},
               @default_client_subject,
               nil,
               nil
             )
  end
end
