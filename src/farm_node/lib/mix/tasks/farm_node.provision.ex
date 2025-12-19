defmodule Mix.Tasks.FarmNode.Provision do
  @shortdoc "Provisions the Farm Node with the Hub"

  @moduledoc """
  Handles the first-boot provisioning of a Farm Node.

  This task guides the user through providing:
  - Hub Address (e.g., https://hub.gaia.coop)
  - Initial Provisioning Key (provided by the cooperative)
  - Farm Identifier (unique name for this farm)

  Once complete, the node will have its mTLS credentials and can
  communicate securely with the Hub.

  ## Usage

      mix farm_node.provision

  ## Interactive Mode

  The task will prompt for:
  - Hub Address
  - Provisioning Key
  - Farm Identifier

  ## Non-Interactive Mode

      mix farm_node.provision --hub-address https://hub.gaia.coop \\
        --provisioning-key SECRET123 \\
        --farm-identifier green-acres
  """

  use Mix.Task

  alias Gaia.FarmNode.HubConnection.Provisioning

  @requirements ["app.config"]

  @impl Mix.Task
  def run(args) do
    # Start the application to ensure dependencies are available
    {:ok, _} = Application.ensure_all_started(:farm_node)

    # Check if already provisioned
    if Provisioning.provisioned?() do
      Mix.shell().error("""

      ❌ This node is already provisioned!

      The node has existing mTLS credentials. If you need to re-provision,
      you must first revoke the existing credentials.

      Location: priv/ssl/
      """)

      System.halt(1)
    end

    # Parse arguments or prompt interactively
    config = parse_args_or_prompt(args)

    # Display confirmation
    display_confirmation(config)

    # Execute provisioning
    execute_provisioning(config)
  end

  defp parse_args_or_prompt(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [
          hub_address: :string,
          provisioning_key: :string,
          farm_identifier: :string
        ],
        aliases: [
          h: :hub_address,
          k: :provisioning_key,
          f: :farm_identifier
        ]
      )

    hub_address = opts[:hub_address] || prompt_hub_address()
    provisioning_key = opts[:provisioning_key] || prompt_provisioning_key()
    farm_identifier = opts[:farm_identifier] || prompt_farm_identifier()

    %{
      hub_address: hub_address,
      provisioning_key: provisioning_key,
      farm_identifier: farm_identifier
    }
  end

  defp prompt_hub_address do
    Mix.shell().info("""

    🌐 Hub Address
    ─────────────────────────────────────────────────────────
    Enter the full URL of your cooperative's Hub server.
    Example: https://hub.gaia.coop
    """)

    address = Mix.shell().prompt("Hub Address:") |> String.trim()

    if valid_url?(address) do
      address
    else
      Mix.shell().error("❌ Invalid URL format. Please try again.")
      prompt_hub_address()
    end
  end

  defp prompt_provisioning_key do
    Mix.shell().info("""

    🔑 Provisioning Key
    ─────────────────────────────────────────────────────────
    Enter the provisioning key provided by your cooperative.
    This is a one-time secret used for initial authentication.
    """)

    key = Mix.shell().prompt("Provisioning Key:") |> String.trim()

    if String.length(key) > 0 do
      key
    else
      Mix.shell().error("❌ Provisioning key cannot be empty.")
      prompt_provisioning_key()
    end
  end

  defp prompt_farm_identifier do
    Mix.shell().info("""

    🚜 Farm Identifier
    ─────────────────────────────────────────────────────────
    Enter a unique identifier for this farm node.
    Use lowercase letters, numbers, and hyphens only.
    Example: green-acres-farm
    """)

    identifier = Mix.shell().prompt("Farm Identifier:") |> String.trim()

    if valid_identifier?(identifier) do
      identifier
    else
      Mix.shell().error("❌ Invalid identifier. Use only lowercase letters, numbers, and hyphens.")
      prompt_farm_identifier()
    end
  end

  defp display_confirmation(config) do
    Mix.shell().info("""

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    📋 Provisioning Configuration
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Hub Address:       #{config.hub_address}
    Farm Identifier:   #{config.farm_identifier}
    Provisioning Key:  #{mask_key(config.provisioning_key)}

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)

    response = Mix.shell().prompt("Proceed with provisioning? (yes/no):")

    unless String.downcase(String.trim(response)) in ["yes", "y"] do
      Mix.shell().info("Provisioning cancelled.")
      System.halt(0)
    end
  end

  defp execute_provisioning(config) do
    Mix.shell().info("\n🔄 Starting provisioning workflow...\n")

    case Provisioning.provision(
           config.hub_address,
           config.provisioning_key,
           config.farm_identifier
         ) do
      :ok ->
        Mix.shell().info("""

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
        - Start the Farm Node application: mix phx.server
        - The node will now communicate securely with the Hub

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """)

      {:error, reason} ->
        Mix.shell().error("""

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

        System.halt(1)
    end
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
end
