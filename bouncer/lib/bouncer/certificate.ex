defmodule Gaia.Bouncer.Certificate do
  @moduledoc """
  Certificate parsing utilities.

  Extracts serial numbers from X.509 certificates.
  """

  require Logger

  @doc """
  Parses a PEM-encoded certificate and extracts the serial number.

  Returns `{:ok, serial}` on success, `{:error, reason}` on failure.

  ## Examples

      iex> cert_pem = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----"
      iex> Gaia.Bouncer.Certificate.parse_serial(cert_pem)
      {:ok, 123456789}

  """
  @spec parse_serial(binary()) :: {:ok, integer()} | {:error, atom()}
  def parse_serial(cert_pem) when is_binary(cert_pem) do
    try do
      case X509.Certificate.from_pem(cert_pem) do
        {:ok, cert} ->
          serial = X509.Certificate.serial(cert)
          {:ok, serial}

        {:error, reason} ->
          Logger.debug("Failed to parse certificate: #{inspect(reason)}")
          {:error, :invalid_certificate}
      end
    rescue
      e ->
        Logger.debug("Exception parsing certificate: #{inspect(e)}")
        {:error, :parse_error}
    end
  end

  def parse_serial(_), do: {:error, :invalid_input}
end
