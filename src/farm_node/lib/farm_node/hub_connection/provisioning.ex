defmodule Gaia.FarmNode.HubConnection.Provisioning do
  @moduledoc """
  Orchestrates the Farm Node provisioning workflow.

  This is the main entry point for the first-boot handshake with the Hub.
  It coordinates:
  - CSR generation
  - HTTP communication with the Hub
  - Secure storage of credentials
  - State transitions
  """

  alias Gaia.FarmNode.HubConnection.Provisioning.CertificateAuthority
  alias Gaia.FarmNode.HubConnection.Provisioning.Client
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  require Logger

  @doc """
  Executes the complete provisioning workflow.

  ## Parameters
  - `hub_address`: The Hub's base URL (e.g., "https://hub.gaia.coop")
  - `provisioning_key`: The initial shared secret provided by the cooperative
  - `farm_identifier`: A unique identifier for this farm (e.g., "green-acres-farm")

  ## Returns
  - `:ok` if provisioning succeeds
  - `{:error, reason}` if any step fails

  ## Examples

      iex> Provisioning.provision(
      ...>   "https://hub.gaia.coop",
      ...>   "secret-key-123",
      ...>   "green-acres"
      ...> )
      :ok
  """
  def provision(hub_address, provisioning_key, farm_identifier) do
    Logger.info("Starting provisioning workflow for farm: #{farm_identifier}")

    # Check if already provisioned
    if Storage.provisioned?() do
      Logger.warning("Node is already provisioned. Aborting.")
      {:error, :already_provisioned}
    else
      execute_provisioning(hub_address, provisioning_key, farm_identifier)
    end
  end

  @doc """
  Checks if this node has been provisioned.
  """
  def provisioned?, do: Storage.provisioned?()

  @doc """
  Returns the status of the provisioning.

  Returns one of:
  - `:unprovisioned` - No credentials exist
  - `:active` - Credentials exist and appear valid
  """
  def status do
    if Storage.provisioned?() do
      :active
    else
      :unprovisioned
    end
  end

  # Private Functions

  defp execute_provisioning(hub_address, provisioning_key, farm_identifier) do
    with {:ok, %{csr: csr, private_key: private_key}} <-
           generate_credentials(farm_identifier),
         {:ok, certificate} <-
           request_certificate(hub_address, provisioning_key, csr, farm_identifier),
         :ok <-
           validate_and_store(certificate, private_key) do
      Logger.info("Provisioning completed successfully")
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Provisioning failed at step: #{inspect(reason)}")
        error
    end
  end

  defp generate_credentials(farm_identifier) do
    Logger.info("Generating CSR and private key...")

    case CertificateAuthority.generate_csr(farm_identifier) do
      {:ok, credentials} ->
        Logger.info("Successfully generated CSR")
        {:ok, credentials}

      {:error, reason} ->
        {:error, {:csr_generation_failed, reason}}
    end
  end

  defp request_certificate(hub_address, provisioning_key, csr, farm_identifier) do
    Logger.info("Requesting certificate from Hub...")

    case Client.request_provisioning(hub_address, provisioning_key, csr, farm_identifier) do
      {:ok, certificate} ->
        {:ok, certificate}

      {:error, reason} ->
        {:error, {:hub_request_failed, reason}}
    end
  end

  defp validate_and_store(certificate, private_key) do
    Logger.info("Validating and storing credentials...")

    with :ok <- CertificateAuthority.validate_certificate(certificate),
         :ok <- Storage.store_credentials(certificate, private_key) do
      :ok
    else
      {:error, reason} ->
        {:error, {:storage_failed, reason}}
    end
  end
end
