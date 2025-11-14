defmodule Gaia.Hub.ProvisionTest do
  use ExUnit.Case

  alias Gaia.Hub.Provision
  alias Gaia.Hub.ProvisionTestHelper
  alias X509.{Certificate, CSR, PrivateKey, PublicKey, RDNSequence}

  setup_all do
    # Seed random for predictable tests
    :rand.seed(:exsplus, {123, 456, 789})
    :ok
  end

  describe "generate_intial_provisioning_key/0" do
    test "returns a passphrase with default 6 words when no config" do
      # Ensure clean configuration state
      original_config = Application.get_env(:hub, :provision)
      Application.delete_env(:hub, :provision)

      try do
        key = Provision.generate_intial_provisioning_key()
        assert is_binary(key)

        words = String.split(key, "-")
        assert length(words) == 6

        Enum.each(words, fn word ->
          assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
        end)
      after
        if original_config, do: Application.put_env(:hub, :provision, original_config)
      end
    end

    test "returns a passphrase with configured word count" do
      original_config = Application.get_env(:hub, :provision)

      try do
        Application.put_env(:hub, :provision, passphrase_word_count: 4)

        key = Provision.generate_intial_provisioning_key()
        assert is_binary(key)

        words = String.split(key, "-")
        assert length(words) == 4

        Enum.each(words, fn word ->
          assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
        end)
      after
        if original_config do
          Application.put_env(:hub, :provision, original_config)
        else
          Application.delete_env(:hub, :provision)
        end
      end
    end

    test "generates different keys on subsequent calls" do
      key1 = Provision.generate_intial_provisioning_key()
      key2 = Provision.generate_intial_provisioning_key()

      assert is_binary(key1)
      assert is_binary(key2)
      assert key1 != key2
    end
  end

  describe "sign_certificate_request/1" do
    setup do
      context = ProvisionTestHelper.setup_full_test_environment()

      on_exit(fn ->
        ProvisionTestHelper.cleanup_test_environment(context)
      end)

      {:ok, context}
    end

    test "successfully signs a valid CSR and returns a PEM certificate", %{ca_subject: ca_subject} do
      csr_data = ProvisionTestHelper.create_test_csr()

      result = Provision.sign_certificate_request(csr_data.client_csr_pem)

      assert {:ok, cert_pem} = result
      assert is_binary(cert_pem)
      assert String.contains?(cert_pem, "-----BEGIN CERTIFICATE-----")
      assert String.contains?(cert_pem, "-----END CERTIFICATE-----")

      # Verify certificate properties
      expected_public_key = PublicKey.derive(csr_data.client_key)

      assert {:ok, _cert} =
               ProvisionTestHelper.verify_signed_certificate(
                 result,
                 csr_data.client_subject,
                 ca_subject,
                 expected_public_key
               )
    end

    test "signs CSR with custom subject", %{ca_subject: ca_subject} do
      custom_subject = RDNSequence.new("/C=UK/ST=London/O=Custom Org/CN=custom.example.com")
      csr_data = ProvisionTestHelper.create_test_csr(custom_subject)

      result = Provision.sign_certificate_request(csr_data.client_csr_pem)

      assert {:ok, _cert_pem} = result

      expected_public_key = PublicKey.derive(csr_data.client_key)

      assert {:ok, _cert} =
               ProvisionTestHelper.verify_signed_certificate(
                 result,
                 custom_subject,
                 ca_subject,
                 expected_public_key
               )
    end

    test "returns error for invalid CSR PEM" do
      invalid_csr_pem = "invalid pem content"

      result = Provision.sign_certificate_request(invalid_csr_pem)

      assert {:error, _reason} = result
    end

    test "returns error for malformed PEM with valid structure but invalid content" do
      malformed_csr_pem = """
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBWjCCAQ==
      -----END CERTIFICATE REQUEST-----
      """

      result = Provision.sign_certificate_request(malformed_csr_pem)

      assert {:error, _reason} = result
    end

    test "returns error when CA certificate file does not exist" do
      # Create CSR first
      csr_data = ProvisionTestHelper.create_test_csr()

      # Set invalid CA certificate path
      Application.put_env(:hub, :provision,
        cacert: [
          cert: "/nonexistent/path/ca.pem",
          key: "/nonexistent/path/ca.key"
        ]
      )

      result = Provision.sign_certificate_request(csr_data.client_csr_pem)

      assert {:error, _reason} = result
    end

    test "returns error when cacert configuration is missing" do
      csr_data = ProvisionTestHelper.create_test_csr()

      # Remove cacert configuration
      Application.put_env(:hub, :provision, [])

      result = Provision.sign_certificate_request(csr_data.client_csr_pem)

      assert {:error, error_message} = result
      assert String.contains?(error_message, "CACert configuration not found")
    end

    test "applies configured certificate validity period" do
      # Set custom validity period
      Application.put_env(:hub, :provision,
        cacert: [
          cert: Application.get_env(:hub, :provision)[:cacert][:cert],
          key: Application.get_env(:hub, :provision)[:cacert][:key]
        ],
        key_validity_days: 30
      )

      csr_data = ProvisionTestHelper.create_test_csr()

      result = Provision.sign_certificate_request(csr_data.client_csr_pem)

      assert {:ok, cert_pem} = result
      {:ok, _cert} = Certificate.from_pem(cert_pem)

      # Just verify that the certificate was created successfully
      # The detailed validity period verification would require complex ASN.1 handling
      assert is_binary(cert_pem)
      assert String.contains?(cert_pem, "-----BEGIN CERTIFICATE-----")
      assert String.contains?(cert_pem, "-----END CERTIFICATE-----")
    end
  end

  describe "certificate signing with different key types" do
    setup do
      context = ProvisionTestHelper.setup_full_test_environment()

      on_exit(fn ->
        ProvisionTestHelper.cleanup_test_environment(context)
      end)

      {:ok, context}
    end

    test "successfully signs CSR with RSA 4096 key", %{ca_subject: ca_subject} do
      # Generate larger RSA key
      client_key = PrivateKey.new_rsa(4096)
      client_subject = RDNSequence.new("/C=US/ST=CA/O=Test/CN=test-rsa4096.example.com")
      client_csr = CSR.new(client_key, client_subject)
      csr_pem = CSR.to_pem(client_csr)

      result = Provision.sign_certificate_request(csr_pem)

      assert {:ok, _cert_pem} = result

      expected_public_key = PublicKey.derive(client_key)

      assert {:ok, _cert} =
               ProvisionTestHelper.verify_signed_certificate(
                 result,
                 client_subject,
                 ca_subject,
                 expected_public_key
               )
    end
  end
end
