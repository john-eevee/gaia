defmodule Gaia.Hub.Provision do
  @moduledoc """
  Module responsible for provisioning operations such as generating
  one-time access keys and signing certificate requests.
  """

  alias Gaia.Hub.Provision.Diceware
  alias X509.Certificate
  alias X509.Certificate.Validity
  alias X509.CSR
  alias X509.PrivateKey
  alias Gaia.Hub.Provision.KeyHash

  @default_passphrase_word_count 6

  @default_key_validity_days 365

  # Lets say they keys are valid for a year, but we will need a renewal halfway through
  # to ensure continued security without user intervention.

  @doc """
  Generates an access key to be used as one-time access credential.

  The generated key is a passphrase that consists of a series of
  capitalized words and numbers, giving an easy to read and type, yet secure key.
  """
  @spec generate_intial_provisioning_key() :: String.t()
  def generate_intial_provisioning_key() do
    provision_config = get_provision_config()
    word_count = get_passphrase_word_count(provision_config)
    Diceware.generate_passphrase(word_count)
  end

  @doc """
  Verifies if the provided provisioning key matches the expected key.
  """
  @spec provisioning_key_valid?(String.t(), String.t()) :: boolean()
  def provisioning_key_valid?(hash, key)
      when is_binary(hash) and is_binary(key) do
    hasher = get_hasher()
    hasher.verify(hash, key)
  end

  @doc """
  Hashes the provisioning key for secure storage.
  """
  @spec hash_provisioning_key(String.t()) :: String.t()
  def hash_provisioning_key(provisioning_key) when is_binary(provisioning_key) do
    hasher = get_hasher()
    hasher.hash(provisioning_key)
  end

  defp get_hasher() do
    # For now, we only have one hasher implementation, so we return it directly.
    # In the future, this could be made configurable.
    KeyHash.Argon
  end

  @doc """
  Signs a certificate signing request (CSR) with the CA's private key.
  """
  @spec sign_certificate_request(binary()) :: {:ok, binary()} | {:error, term()}
  def sign_certificate_request(csr_pem) when is_binary(csr_pem) do
    with provision_config <- get_provision_config(),
         {:ok, ca_cert, ca_key} <- load_ca_credentials(provision_config),
         {:ok, csr} <- parse_csr(csr_pem) do
      create_signed_certificate(csr, ca_cert, ca_key, provision_config)
    end
  end

  defp load_ca_credentials(provision_config) do
    with {:ok, cacert_config} <- get_cacert_config(provision_config),
         {:ok, {ca_cert_pem, ca_key_pem}} <- get_ca_files(cacert_config),
         {:ok, ca_cert} <- Certificate.from_pem(ca_cert_pem),
         {:ok, ca_key} <- PrivateKey.from_pem(ca_key_pem) do
      {:ok, ca_cert, ca_key}
    end
  end

  defp parse_csr(csr_pem) do
    CSR.from_pem(csr_pem)
  end

  defp create_signed_certificate(csr, ca_cert, ca_key, provision_config) do
    validity = fn ->
      days = get_default_key_validity_days(provision_config)
      now = DateTime.utc_now()
      random_drift = -1 * :rand.uniform(60)
      not_before = DateTime.add(now, random_drift, :second)
      not_after = DateTime.add(not_before, days, :day)
      Validity.new(not_before, not_after)
    end

    subject = CSR.subject(csr)
    public_key = CSR.public_key(csr)
    cert = Certificate.new(public_key, subject, ca_cert, ca_key, validity: validity.())
    cert_pem = Certificate.to_pem(cert)
    {:ok, cert_pem}
  end

  defp get_ca_files(cacert_config) do
    cert_pem_file = Keyword.fetch!(cacert_config, :cert)
    key_pem_file = Keyword.fetch!(cacert_config, :key)

    with {:ok, ca_cert_pem} <- File.read(cert_pem_file),
         {:ok, ca_key_pem} <- File.read(key_pem_file) do
      {:ok, {ca_cert_pem, ca_key_pem}}
    end
  end

  defp get_provision_config() do
    Application.get_env(:hub, :provision)
  end

  defp get_cacert_config(provision_config) do
    case Keyword.get(provision_config, :cacert) do
      nil ->
        {:error, ~s(CACert configuration not found in application environment.

Please ensure that the :hub application is properly configured with the :cacert settings.

Expected configuration format:

    config :hub,
      provision: [
        cacert: [
          cert: "path/to/ca_certificate.pem",
          key: "path/to/ca_private_key.key"
        ]
      ])}

      cacert_config ->
        {:ok, cacert_config}
    end
  end

  defp get_passphrase_word_count(provision_config) when is_list(provision_config) do
    Keyword.get(provision_config, :passphrase_word_count, @default_passphrase_word_count)
  end

  defp get_passphrase_word_count(_), do: @default_passphrase_word_count

  defp get_default_key_validity_days(provision_config) when is_list(provision_config) do
    Keyword.get(provision_config, :key_validity_days, @default_key_validity_days)
  end

  defp get_default_key_validity_days(_), do: @default_key_validity_days
end
