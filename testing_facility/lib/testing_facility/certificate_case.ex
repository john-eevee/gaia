defmodule Gaia.TestingFacility.CertificateCase do
  @moduledoc """
  Test helper module for provision tests.
  Provides utilities for setting up CA certificates, temporary files,
  and application configuration needed for provision testing.
  """

  alias X509.Certificate
  alias X509.CSR
  alias X509.PrivateKey
  alias X509.RDNSequence

  @doc """
  Creates a CA certificate and key pair.
  """
  def create_ca_certificate() do
    # Generate CA key and certificate
    ca_key = PrivateKey.new_rsa(2048)
    ca_subject = RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
    ca_cert = Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

    {ca_key, ca_cert, ca_subject}
  end

  @doc """
  Creates a signed client certificate.
  """
  @spec create_signed_client_certificate(
          {PrivateKey.t(), Certificate.t(), RDNSequence.t()}
          | nil
        ) ::
          {Certificate.t(), binary(), binary()}
  def create_signed_client_certificate(root_ca \\ nil) do
    {ca_key, ca_cert, _ca_subject} = root_ca || create_ca_certificate()

    # Create client key and CSR
    client_key = PrivateKey.new_rsa(2048)
    client_subject = RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")
    csr = CSR.new(client_key, client_subject)

    # Sign CSR with CA to create client certificate
    cert = Certificate.new(CSR.public_key(csr), client_subject, ca_cert, ca_key)
    pem = Certificate.to_pem(cert)
    serial = Integer.to_string(X509.Certificate.serial(cert), 16) |> String.upcase()
    {cert, pem, serial}
  end

  @doc """
  Sets up a test CA environment with temporary certificates and keys.
  Returns a context map with all necessary test data.
  """
  def setup_test_ca(context \\ %{}) do
    {ca_key, ca_cert, ca_subject} = create_ca_certificate()

    # Create temporary directory and file paths
    temp_dir = System.tmp_dir!()
    ca_cert_path = Path.join(temp_dir, "test_ca_#{:rand.uniform(1000)}.pem")
    ca_key_path = Path.join(temp_dir, "test_ca_#{:rand.uniform(1000)}.key")

    # Write CA certificate and key to temporary files
    File.write!(ca_cert_path, Certificate.to_pem(ca_cert))
    File.write!(ca_key_path, PrivateKey.to_pem(ca_key))

    context
    |> Map.put(:ca_key, ca_key)
    |> Map.put(:ca_cert, ca_cert)
    |> Map.put(:ca_subject, ca_subject)
    |> Map.put(:ca_cert_path, ca_cert_path)
    |> Map.put(:ca_key_path, ca_key_path)
    |> Map.put(:temp_files, [ca_cert_path, ca_key_path])
  end

  @doc """
  Creates a test CSR with the given subject or a default test subject.
  """
  def create_test_csr(subject \\ nil) do
    client_key = PrivateKey.new_rsa(2048)
    client_subject = subject || RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")
    client_csr = CSR.new(client_key, client_subject)

    %{
      client_key: client_key,
      client_subject: client_subject,
      client_csr: client_csr,
      client_csr_pem: CSR.to_pem(client_csr)
    }
  end

  @doc """
  Sets up application configuration for provision testing.
  Stores the original configuration and applies test configuration.
  """
  def setup_provision_config(context) do
    # Store original configuration
    original_provision_config = Application.get_env(:hub, :provision)

    # Set test configuration
    test_config = [
      cacert: [
        cert: context.ca_cert_path,
        key: context.ca_key_path
      ],
      passphrase_word_count: 6,
      key_validity_days: 365
    ]

    Application.put_env(:hub, :provision, test_config)

    context
    |> Map.put(:original_provision_config, original_provision_config)
    |> Map.put(:test_provision_config, test_config)
  end

  @doc """
  Cleans up test environment including temporary files and application configuration.
  """
  def cleanup_test_environment(context) do
    # Restore original application configuration
    if context[:original_provision_config] do
      Application.put_env(:hub, :provision, context.original_provision_config)
    else
      Application.delete_env(:hub, :provision)
    end

    # Clean up temporary files
    if context[:temp_files] do
      Enum.each(context.temp_files, &File.rm/1)
    end

    :ok
  end

  @doc """
  Full setup for provision tests that need CA environment.
  Combines CA setup, configuration setup, and returns context for cleanup.
  """
  def setup_full_test_environment do
    %{}
    |> setup_test_ca()
    |> setup_provision_config()
  end

  @doc """
  Verifies that a certificate is properly signed by the CA and matches expected properties.
  """
  def verify_signed_certificate(
        cert_result,
        expected_subject,
        expected_ca_subject,
        expected_public_key
      ) do
    case cert_result do
      {:ok, cert_pem} when is_binary(cert_pem) ->
        {:ok, cert} = Certificate.from_pem(cert_pem)

        verify_certificate_properties(
          cert,
          expected_subject,
          expected_ca_subject,
          expected_public_key
        )

      {:ok, cert} ->
        verify_certificate_properties(
          cert,
          expected_subject,
          expected_ca_subject,
          expected_public_key
        )

      error ->
        error
    end
  end

  defp verify_issuer(cert, expected_ca_subject) do
    issuer_string = RDNSequence.to_string(Certificate.issuer(cert))
    expected_issuer_string = RDNSequence.to_string(expected_ca_subject)

    if issuer_string == expected_issuer_string do
      :ok
    else
      {:error,
       "Certificate issuer mismatch. Expected: #{expected_issuer_string}, Got: #{issuer_string}"}
    end
  end

  defp verify_subject(cert, expected_subject) do
    subject_string = RDNSequence.to_string(Certificate.subject(cert))
    expected_subject_string = RDNSequence.to_string(expected_subject)

    if subject_string == expected_subject_string do
      :ok
    else
      {:error,
       "Certificate subject mismatch. Expected: #{expected_subject_string}, Got: #{subject_string}"}
    end
  end

  defp verify_public_key(cert, expected_public_key) do
    cert_public_key = Certificate.public_key(cert)

    if cert_public_key == expected_public_key do
      :ok
    else
      {:error, "Certificate public key mismatch"}
    end
  end

  defp verify_certificate_properties(
         cert,
         expected_subject,
         expected_ca_subject,
         expected_public_key
       ) do
    with :ok <- verify_issuer(cert, expected_ca_subject),
         :ok <- verify_subject(cert, expected_subject),
         :ok <- verify_public_key(cert, expected_public_key) do
      {:ok, cert}
    end
  end
end
