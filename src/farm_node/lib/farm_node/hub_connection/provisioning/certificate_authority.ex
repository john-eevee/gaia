defmodule Gaia.FarmNode.HubConnection.Provisioning.CertificateAuthority do
  @moduledoc """
  Handles CSR (Certificate Signing Request) generation and certificate management.

  This module is responsible for:
  - Generating private keys
  - Creating CSRs for the provisioning handshake
  - Parsing and validating certificates received from the Hub
  """

  @doc """
  Generates a new RSA private key and CSR for provisioning.

  Returns `{:ok, %{private_key: pem_string, csr: pem_string}}` or `{:error, reason}`.
  """
  def generate_csr(farm_identifier) do
    with {:ok, private_key} <- generate_private_key(),
         {:ok, csr} <- create_csr(private_key, farm_identifier) do
      {:ok, %{private_key: private_key, csr: csr}}
    end
  end

  @doc """
  Validates that a certificate PEM string is well-formed.
  """
  def validate_certificate(cert_pem) when is_binary(cert_pem) do
    case :public_key.pem_decode(cert_pem) do
      [{type, _, _} | _] when type in [:Certificate, ~c"Certificate", ~c"CERTIFICATE"] -> :ok
      _ -> {:error, :invalid_certificate_format}
    end
  rescue
    _ -> {:error, :invalid_certificate_pem}
  end

  # Private Functions

  defp generate_private_key do
    try do
      # Generate 4096-bit RSA key for strong security
      private_key = :public_key.generate_key({:rsa, 4096, 65537})
      pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, private_key)
      pem_string = :public_key.pem_encode([pem_entry])

      {:ok, pem_string}
    rescue
      error -> {:error, {:key_generation_failed, error}}
    end
  end

  defp create_csr(private_key_pem, farm_identifier) do
    try do
      # Use X509.CSR for proper CSR generation
      [{:RSAPrivateKey, der, _}] = :public_key.pem_decode(private_key_pem)
      private_key = :public_key.der_decode(:RSAPrivateKey, der)

      # Build distinguished name
      subject =
        X509.RDNSequence.new("/CN=farm-node-#{farm_identifier}/O=Gaia Cooperative Farm/C=US")

      # Create CSR
      csr = X509.CSR.new(private_key, subject)

      # Encode to PEM
      pem_string = X509.CSR.to_pem(csr)

      {:ok, pem_string}
    rescue
      error -> {:error, {:csr_generation_failed, error}}
    end
  end
end
