defmodule Gaia.FarmNode.HubConnection.Provisioning.Storage do
  @moduledoc """
  Handles secure storage of mTLS certificates and private keys.

  Certificates are stored in `priv/ssl/` with restricted permissions.
  This module ensures that:
  - Files are written with appropriate permissions (0600 for keys, 0644 for certs)
  - Directory structure is created if it doesn't exist
  - Files are NOT stored in version control or the database
  """

  require Logger

  @default_ssl_dir "priv/ssl"
  @cert_file "farm_node_cert.pem"
  @key_file "farm_node_key.pem"
  @state_file "provisioning_state.json"

  @type extract_der_result :: [
          cert: binary(),
          keys: [key_der: binary(), type: atom()]
        ]

  defp ssl_dir do
    Application.get_env(:farm_node, :ssl_dir, @default_ssl_dir)
  end

  @spec store_credentials(any(), any()) ::
          :ok
          | {:error,
             atom()
             | {:cannot_create_directory, atom()}
             | {:cannot_encode_state,
                %{
                  :__exception__ => true,
                  :__struct__ => Jason.EncodeError | Protocol.UndefinedError,
                  optional(atom()) => any()
                }}
             | {:cannot_write_cert, atom() | pos_integer()}
             | {:cannot_write_key, atom() | pos_integer()}}
  @doc """
  Stores the mTLS certificate and private key securely.

  Returns `:ok` or `{:error, reason}`.
  """
  def store_credentials(certificate_pem, private_key_pem) do
    with :ok <- ensure_ssl_directory(),
         :ok <- write_private_key(private_key_pem),
         :ok <- write_certificate(certificate_pem),
         :ok <- mark_as_provisioned() do
      Logger.info("Successfully stored mTLS credentials in #{ssl_dir()}")
      :ok
    end
  end

  @doc """
  Checks if the node has been provisioned (has valid credentials).
  """
  def provisioned? do
    cert_path = Path.join(ssl_dir(), @cert_file)
    key_path = Path.join(ssl_dir(), @key_file)

    File.exists?(cert_path) and File.exists?(key_path)
  end

  @doc """
  Returns the paths to the certificate and key files.

  Returns `{:ok, %{cert: path, key: path}}` or `{:error, :not_provisioned}`.
  """
  def get_credential_paths do
    if provisioned?() do
      {:ok,
       %{
         cert: Path.join(ssl_dir(), @cert_file),
         key: Path.join(ssl_dir(), @key_file)
       }}
    else
      {:error, :not_provisioned}
    end
  end

  @doc """
  Loads the certificate and key from disk.

  Returns `{:ok, %{cert: pem_string, key: pem_string}}` or `{:error, reason}`.
  """
  def load_credentials do
    with {:ok, paths} <- get_credential_paths(),
         {:ok, cert} <- File.read(paths.cert),
         {:ok, key} <- File.read(paths.key) do
      {:ok, %{cert: cert, key: key}}
    end
  end

  @doc """
  Revokes stored credentials (e.g., when the Hub revokes access).
  """
  def revoke_credentials do
    cert_path = Path.join(ssl_dir(), @cert_file)
    key_path = Path.join(ssl_dir(), @key_file)
    state_path = Path.join(ssl_dir(), @state_file)

    File.rm(cert_path)
    File.rm(key_path)
    File.rm(state_path)

    Logger.warning("mTLS credentials have been revoked and removed")
    :ok
  end

  @doc """
  Extract DERs from the provisioned certificate and keys.
  """
  @spec extract_ders() :: {:ok, extract_der_result()} | {:error, term()}
  def extract_ders() do
    with {:ok, creds} <- Provisioning.Storage.load_credentials(),
         {:ok, cert} <- X509.Certificate.from_pem(creds.cert),
         cert_der = X509.Certificate.to_der(cert),
         {:ok, key} <- X509.PrivateKey.from_pem(creds.key),
         key_der = X509.PrivateKey.to_der(key) do
      result = [cert: cert_der, keys: [key_der: key_der, type: get_key_type(key)]]
      {:ok, result}
    end
  end

  defp get_key_type(key) do
    case key do
      {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} -> :RSAPrivateKey
      {:ECPrivateKey, _, _, _, _} -> :ECPrivateKey
      {:PrivateKeyInfo, _} -> :PrivateKeyInfo
      _ -> :RSAPrivateKey
    end
  end

  # Private Functions

  defp ensure_ssl_directory do
    dir = ssl_dir()

    case File.mkdir_p(dir) do
      :ok ->
        # Set directory permissions to 0700 (owner only)
        case System.cmd("chmod", ["700", dir]) do
          {_, 0} -> :ok
          _ -> {:error, :cannot_set_permissions}
        end

      {:error, reason} ->
        {:error, {:cannot_create_directory, reason}}
    end
  end

  defp write_private_key(pem_content) do
    path = Path.join(ssl_dir(), @key_file)

    with :ok <- File.write(path, pem_content),
         {_, 0} <- System.cmd("chmod", ["600", path]) do
      :ok
    else
      {:error, reason} -> {:error, {:cannot_write_key, reason}}
      _ -> {:error, :cannot_set_key_permissions}
    end
  end

  defp write_certificate(pem_content) do
    path = Path.join(ssl_dir(), @cert_file)

    with :ok <- File.write(path, pem_content),
         {_, 0} <- System.cmd("chmod", ["644", path]) do
      :ok
    else
      {:error, reason} -> {:error, {:cannot_write_cert, reason}}
      _ -> {:error, :cannot_set_cert_permissions}
    end
  end

  defp mark_as_provisioned do
    path = Path.join(ssl_dir(), @state_file)

    state = %{
      provisioned_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      status: "active"
    }

    case Jason.encode(state) do
      {:ok, json} -> File.write(path, json)
      {:error, reason} -> {:error, {:cannot_encode_state, reason}}
    end
  end
end
