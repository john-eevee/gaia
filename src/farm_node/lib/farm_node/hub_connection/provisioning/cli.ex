defmodule Gaia.FarmNode.HubConnection.Provisioning.CLI do
  @moduledoc """
  CLI interface for provisioning that works in both Mix and Release environments.

  This module provides functions that can be invoked from:
  - Mix tasks (development)
  - Release remote console
  - Release custom commands

  ## Usage in Release

      # Interactive mode
      bin/farm_node rpc "Gaia.FarmNode.HubConnection.Provisioning.CLI.run_interactive()"

      # Non-interactive mode
      bin/farm_node rpc "Gaia.FarmNode.HubConnection.Provisioning.CLI.run([
        hub_address: \"https://hub.gaia.coop\",
        provisioning_key: \"SECRET123\",
        farm_identifier: \"green-acres\"
      ])"
  """

  alias Gaia.FarmNode.HubConnection.Provisioning

  @doc """
  Run provisioning with the given options.

  ## Options

    * `:hub_address` - Hub URL (required)
    * `:provisioning_key` - One-time provisioning key (required)
    * `:farm_identifier` - Unique farm identifier (required)
    * `:skip_confirmation` - Skip confirmation prompt (default: false)

  ## Examples

      iex> Gaia.FarmNode.HubConnection.Provisioning.CLI.run(
      ...>   hub_address: "https://hub.gaia.coop",
      ...>   provisioning_key: "SECRET123",
      ...>   farm_identifier: "green-acres",
      ...>   skip_confirmation: true
      ...> )
      :ok
  """
  def run(opts) when is_list(opts) do
    # Ensure application is started
    Application.ensure_all_started(:farm_node)

    # Check if already provisioned
    if Provisioning.provisioned?() do
      error_message("""

      ❌ This node is already provisioned!

      The node has existing mTLS credentials. If you need to re-provision,
      you must first revoke the existing credentials.

      Location: priv/ssl/
      """)

      {:error, :already_provisioned}
    else
      config = %{
        hub_address: Keyword.fetch!(opts, :hub_address),
        provisioning_key: Keyword.fetch!(opts, :provisioning_key),
        farm_identifier: Keyword.fetch!(opts, :farm_identifier)
      }

      skip_confirmation = Keyword.get(opts, :skip_confirmation, false)

      unless skip_confirmation do
        display_confirmation(config)

        unless confirm?() do
          info_message("Provisioning cancelled.")
          {:error, :cancelled}
        end
      end

      execute_provisioning(config)
    end
  end

  @doc """
  Run provisioning in interactive mode, prompting for all required values.
  """
  def run_interactive do
    # Ensure application is started
    Application.ensure_all_started(:farm_node)

    # Check if already provisioned
    if Provisioning.provisioned?() do
      error_message("""

      ❌ This node is already provisioned!

      The node has existing mTLS credentials. If you need to re-provision,
      you must first revoke the existing credentials.

      Location: priv/ssl/
      """)

      {:error, :already_provisioned}
    else
      config = %{
        hub_address: prompt_hub_address(),
        provisioning_key: prompt_provisioning_key(),
        farm_identifier: prompt_farm_identifier()
      }

      display_confirmation(config)

      if confirm?() do
        execute_provisioning(config)
      else
        info_message("Provisioning cancelled.")
        {:error, :cancelled}
      end
    end
  end

  # Private Functions

  defp execute_provisioning(config) do
    info_message("\n🔄 Starting provisioning workflow...\n")

    case Provisioning.provision(
           config.hub_address,
           config.provisioning_key,
           config.farm_identifier
         ) do
      :ok ->
        info_message("""

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        ✅ Provisioning Successful!
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        Your Farm Node has been successfully provisioned with the Hub.

        📁 Credentials stored in: priv/ssl/

        ⚠️  IMPORTANT SECURITY NOTES:
        1. Never commit the priv/ssl/ directory to version control
        2. Ensure priv/ssl/ has restricted permissions (700)
        3. Back up your credentials securely

        Next steps:
        - Restart the Farm Node application
        - The node will now communicate securely with the Hub

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """)

        :ok

      {:error, reason} ->
        error_message("""

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        ❌ Provisioning Failed
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        Reason: #{format_error(reason)}

        Please check:
        1. Hub address is correct and reachable
        2. Provisioning key is valid
        3. Network connectivity
        4. Hub server logs for more details

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """)

        {:error, reason}
    end
  end

  defp prompt_hub_address do
    info_message("""

    🌐 Hub Address
    ─────────────────────────────────────────────────────────
    Enter the full URL of your cooperative's Hub server.
    Example: https://hub.gaia.coop
    """)

    address = prompt("Hub Address:") |> String.trim()

    if valid_url?(address) do
      address
    else
      error_message("❌ Invalid URL format. Please try again.")
      prompt_hub_address()
    end
  end

  defp prompt_provisioning_key do
    info_message("""

    🔑 Provisioning Key
    ─────────────────────────────────────────────────────────
    Enter the provisioning key provided by your cooperative.
    This is a one-time secret used for initial authentication.
    """)

    key = prompt("Provisioning Key:") |> String.trim()

    if String.length(key) > 0 do
      key
    else
      error_message("❌ Provisioning key cannot be empty.")
      prompt_provisioning_key()
    end
  end

  defp prompt_farm_identifier do
    info_message("""

    🚜 Farm Identifier
    ─────────────────────────────────────────────────────────
    Enter a unique identifier for this farm node.
    Use lowercase letters, numbers, and hyphens only.
    Example: green-acres-farm
    """)

    identifier = prompt("Farm Identifier:") |> String.trim()

    if valid_identifier?(identifier) do
      identifier
    else
      error_message("❌ Invalid identifier. Use only lowercase letters, numbers, and hyphens.")
      prompt_farm_identifier()
    end
  end

  defp display_confirmation(config) do
    info_message("""

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    📋 Provisioning Configuration
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Hub Address:       #{config.hub_address}
    Farm Identifier:   #{config.farm_identifier}
    Provisioning Key:  #{mask_key(config.provisioning_key)}

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)
  end

  defp confirm? do
    response = prompt("Proceed with provisioning? (yes/no):")
    String.downcase(String.trim(response)) in ["yes", "y"]
  end

  # Helper Functions

  defp valid_url?(url) do
    uri = URI.parse(url)
    uri.scheme in ["http", "https"] and uri.host != nil
  end

  defp valid_identifier?(identifier) do
    Regex.match?(~r/^[a-z0-9][a-z0-9\-]*[a-z0-9]$/, identifier)
  end

  defp mask_key(key) do
    len = String.length(key)

    cond do
      len <= 8 ->
        String.duplicate("*", len)

      true ->
        String.slice(key, 0..3) <> String.duplicate("*", len - 8) <> String.slice(key, -4..-1)
    end
  end

  defp format_error(:invalid_provisioning_key), do: "Invalid provisioning key"
  defp format_error(:farm_already_provisioned), do: "Farm identifier already registered with Hub"

  defp format_error({:hub_request_failed, reason}),
    do: "Hub communication error: #{inspect(reason)}"

  defp format_error({:csr_generation_failed, reason}),
    do: "Certificate generation error: #{inspect(reason)}"

  defp format_error({:storage_failed, reason}), do: "Storage error: #{inspect(reason)}"
  defp format_error(reason), do: inspect(reason)

  # IO abstraction to work in both Mix and Release environments

  defp info_message(msg), do: IO.puts(msg)
  defp error_message(msg), do: IO.puts(:stderr, msg)

  defp prompt(msg) do
    IO.gets(msg)
  end
end
