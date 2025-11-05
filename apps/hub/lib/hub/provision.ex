defmodule Gaia.Hub.Provision do
  @moduledoc """
  Provision module to issue certificates and access keys,
  as well as verify them for secure communications within the Hub.

  """
  alias Gaia.Hub.Provision.Diceware

  @passphrase_word_count 6

  # Lets say they keys are valid for a year, but we will need a renewal halfway through
  # to ensure continued security without user intervention.
  @default_key_validity_days 365

  @doc """
  Generates an access key to be used as one-time access credential.

  The generated key is a passphrase that consists of a series of
  capitalized words and numbers, giving an easy to read and type, yet secure key.

  """
  def generate_one_time_access_key() do
    Diceware.generate_passphrase(@passphrase_word_count)
  end

  def sign_certificate_request(csr_pem) when is_binary(csr_pem) do
    {ca_cert_pem, ca_key_pem} = get_ca_files()

    with {:ok, csr} <- X509.CSR.from_pem(csr_pem),
         {:ok, ca_cert} <- X509.Certificate.from_pem(ca_cert_pem),
         {:ok, ca_key} <- X509.PrivateKey.from_pem(ca_key_pem),
         subject <- X509.CSR.subject(csr) do
      csr
      |> X509.CSR.public_key()
      |> X509.Certificate.new(subject, ca_cert, ca_key)
    end
  end

  defp get_ca_files do
    cacert_config = get_cacert_config()

    cert_pem_file = Keyword.fetch!(cacert_config, :cert)
    key_pem_file = Keyword.fetch!(cacert_config, :key)

    ca_cert_pem = File.read!(cert_pem_file)
    ca_key_pem = File.read!(key_pem_file)
    {ca_cert_pem, ca_key_pem}
  end

  defp get_cacert_config() do
    config = Application.get_env(:hub, :cacert)

    if is_nil(config) do
      raise ~s(CACert configuration not found in application environment.

      Please ensure that the :hub application is properly configured with the :cacert settings.

      Expected configuration format:

          config :hub,
            cacert: [
              cert: "path/to/ca_certificate.pem",
              key: "path/to/ca_private_key.key"
            ]
      )
    end

    config
  end
end
