defmodule Gaia.Bouncer.Certificate do
  @moduledoc """
  Certificate parsing utilities.

  Extracts serial numbers from X.509 certificates.
  """

  require Logger

  @doc """
  Parses a PEM-encoded certificate and extracts the serial number as a hexadecimal string.

  Returns `{:ok, serial_hex}` on success, `{:error, reason}` on failure.

  ## Examples

      iex> cert_pem = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----"
      iex> Gaia.Bouncer.Certificate.parse_serial(cert_pem)
      {:ok, "1A2B3C4D5E6F"}

  """
  @spec parse_serial(binary()) :: {:ok, String.t()} | {:error, atom()}
  def parse_serial(cert_pem) when is_binary(cert_pem) do
    case X509.Certificate.from_pem(cert_pem) do
      {:ok, cert} ->
        serial = X509.Certificate.serial(cert)
        # Convert integer serial to uppercase hexadecimal string
        serial_hex = Integer.to_string(serial, 16)
        {:ok, serial_hex}

      {:error, reason} ->
        Logger.debug("Failed to parse certificate: #{inspect(reason)}")
        {:error, :invalid_certificate}
    end
  rescue
    e ->
      Logger.debug("Exception parsing certificate: #{inspect(e)}")
      {:error, :parse_error}
  end

  def parse_serial(_), do: {:error, :invalid_input}
end
