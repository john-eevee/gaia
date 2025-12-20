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

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI

  @requirements ["app.config"]

  @impl Mix.Task
  def run(args) do
    # Parse arguments
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

    # Delegate to CLI module
    result =
      if Enum.empty?(opts) do
        CLI.run_interactive()
      else
        CLI.run(opts)
      end

    # Exit with appropriate code
    case result do
      :ok -> :ok
      {:error, _} -> System.halt(1)
    end
  end
end
