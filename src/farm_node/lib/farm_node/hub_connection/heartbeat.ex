defmodule Gaia.FarmNode.HubConnection.Heartbeat do
  @moduledoc """
  Manages periodic heartbeat communication with the Hub using mTLS authentication.

  This GenServer:
  - Sends periodic heartbeats to the Hub's `/api/v1/heartbeat` endpoint every 5 minutes
  - Uses the provisioned mTLS certificate for authentication
  - Handles successful responses (200 OK)
  - Handles revocation responses (403 Forbidden) by stopping all Hub communication
  - Handles network errors gracefully (logs and continues, as the node may be offline)

  The heartbeat serves as both a liveness check and a security verification mechanism.
  """

  use GenServer
  require Logger

  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  @heartbeat_interval :timer.minutes(5)
  @heartbeat_endpoint "/api/v1/heartbeat"
  @timeout 30_000

  ## Client API

  @doc """
  Starts the Heartbeat GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Check if provisioned before starting heartbeat
    if Storage.provisioned?() do
      hub_address = Application.get_env(:farm_node, :hub_address)

      if hub_address do
        Logger.info("Heartbeat service starting with hub: #{hub_address}")
        state = %{
          hub_address: hub_address,
          revoked: false,
          timer_ref: schedule_heartbeat(0)
        }
        {:ok, state}
      else
        Logger.warning("Heartbeat service not started: no hub_address configured")
        {:ok, %{hub_address: nil, revoked: true, timer_ref: nil}}
      end
    else
      Logger.info("Heartbeat service not started: node is not provisioned")
      {:ok, %{hub_address: nil, revoked: true, timer_ref: nil}}
    end
  end

  @impl true
  def handle_info(:send_heartbeat, %{revoked: true} = state) do
    # If revoked, don't send heartbeats
    {:noreply, state}
  end

  def handle_info(:send_heartbeat, state) do
    send_heartbeat_request(state)
    timer_ref = schedule_heartbeat(@heartbeat_interval)
    {:noreply, %{state | timer_ref: timer_ref}}
  end

  ## Private Functions

  defp schedule_heartbeat(interval) do
    Process.send_after(self(), :send_heartbeat, interval)
  end

  defp send_heartbeat_request(state) do
    url = build_url(state.hub_address, @heartbeat_endpoint)

    case load_credentials() do
      {:ok, credentials} ->
        make_heartbeat_request(url, credentials)

      {:error, reason} ->
        Logger.error("Failed to load mTLS credentials for heartbeat: #{inspect(reason)}")
        :error
    end
  end

  defp load_credentials do
    with {:ok, paths} <- Storage.get_credential_paths(),
         {:ok, cert_pem} <- File.read(paths.cert),
         {:ok, key_pem} <- File.read(paths.key) do
      {:ok, %{cert: cert_pem, key: key_pem}}
    end
  end

  defp make_heartbeat_request(url, credentials) do
    version = Application.spec(:farm_node, :vsn)

    headers = [
      {"user-agent", "Gaia-FarmNode/#{version}"}
    ]

    # Allow injection of a test HTTP client via application config for
    # deterministic testing. Defaults to Req in production.
    http_client = Application.get_env(:farm_node, :http_client, Req)

    # Parse PEM certificates and keys for mTLS
    # Extract DER from PEM for SSL options
    with {:ok, cert_der} <- extract_cert_der(credentials.cert),
         {:ok, key_tuple} <- extract_key_der(credentials.key) do
      # Configure mTLS by providing the certificate and private key
      # SSL options expect DER-encoded cert and key tuple
      connect_options = [
        transport_opts: [
          cert: cert_der,
          key: key_tuple,
          verify: :verify_peer,
          cacerts: :public_key.cacerts_get()
        ]
      ]

      case http_client.get(url,
             headers: headers,
             receive_timeout: @timeout,
             retry: false,
             connect_options: connect_options
           ) do
        {:ok, %{status: 200}} ->
          Logger.debug("Heartbeat successful")
          :ok

        {:ok, %{status: 403}} ->
          Logger.error("Heartbeat returned 403 Forbidden - certificate has been revoked")
          handle_revocation()
          :revoked

        {:ok, %{status: status}} ->
          Logger.warning("Heartbeat returned unexpected status: #{status}")
          :error

        {:error, exception} ->
          # Network errors - node might be offline, just log and continue
          Logger.warning("Heartbeat failed (possibly offline): #{inspect(exception)}")
          :error
      end
    else
      {:error, reason} ->
        Logger.error("Failed to parse mTLS credentials: #{inspect(reason)}")
        :error
    end
  end

  defp extract_cert_der(pem_string) do
    try do
      cert = X509.Certificate.from_pem!(pem_string)
      cert_der = X509.Certificate.to_der(cert)
      {:ok, cert_der}
    rescue
      _ -> {:error, :invalid_certificate}
    end
  end

  defp extract_key_der(pem_string) do
    try do
      key = X509.PrivateKey.from_pem!(pem_string)
      # X509.PrivateKey.to_der returns the key in DER format
      key_der = X509.PrivateKey.to_der(key)
      # Determine key type from the key structure
      key_type = case key do
        {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} -> :RSAPrivateKey
        {:ECPrivateKey, _, _, _, _} -> :ECPrivateKey
        {:PrivateKeyInfo, _} -> :PrivateKeyInfo
        _ -> :RSAPrivateKey  # Default to RSA for compatibility
      end
      {:ok, {key_type, key_der}}
    rescue
      _ -> {:error, :invalid_key}
    end
  end

  defp build_url(hub_address, path) do
    # Normalize hub_address (remove trailing slash if present)
    base = String.trim_trailing(hub_address, "/")
    "#{base}#{path}"
  end

  defp handle_revocation do
    Logger.error("Certificate revoked - stopping all Hub communication")
    # Revoke credentials locally
    Storage.revoke_credentials()
    # Update state to prevent further heartbeats
    GenServer.cast(__MODULE__, :mark_revoked)
  end

  @impl true
  def handle_cast(:mark_revoked, state) do
    # Cancel the timer if it exists
    if state.timer_ref do
      Process.cancel_timer(state.timer_ref)
    end

    {:noreply, %{state | revoked: true, timer_ref: nil}}
  end
end
