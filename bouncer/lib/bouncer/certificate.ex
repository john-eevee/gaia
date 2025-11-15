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

  def valid?(serial) do
    query = """
    SELECT status
    FROM certificate_status
    WHERE certificate_serial = $1
    LIMIT 1
    """

    database = get_database()

    case database.query(query, [serial]) do
      {:ok, %{rows: [[status]]}} ->
        {:ok, normalize_status(status)}

      {:ok, %{rows: []}} ->
        {:ok, :unknown}

      {:error, reason} ->
        Logger.error("Database query failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Normalize status boolean to atoms
  # true (1) = valid, false (0) = revoked
  defp normalize_status(true), do: :valid
  defp normalize_status(false), do: :revoked
  defp normalize_status(_), do: :unknown
 
  defp get_database() do
    Application.get_env(:bouncer, :database_module, Gaia.Bouncer.PostgrexDatabase)
  end
end
