defmodule Gaia.FarmNode.HubConnection.Provisioning.CliTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  setup do
    Application.ensure_all_started(:farm_node)
    # Ensure clean state
    Storage.revoke_credentials()
    :ok
  end

  test "run/1 returns error when node already provisioned" do
    # Write dummy credentials to mark the node as provisioned
    Storage.store_credentials("CERT", "KEY")

    assert {:error, :already_provisioned} =
             CLI.run(hub_address: "https://hub", provisioning_key: "k", farm_identifier: "f")

    # Cleanup
    Storage.revoke_credentials()
  end
end
