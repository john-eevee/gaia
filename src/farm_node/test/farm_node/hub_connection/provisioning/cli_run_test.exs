defmodule Gaia.FarmNode.HubConnection.Provisioning.CliMoreTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI

  setup do
    Application.ensure_all_started(:farm_node)
    # Ensure clean provisioning state
    Gaia.FarmNode.HubConnection.Provisioning.Storage.revoke_credentials()
    :ok
  end

  test "run/1 performs provisioning when skip_confirmation true" do
    defmodule ClientSuccess do
      def post(_url, _opts) do
        key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(key, "/CN=hub-ok")
        {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
      end
    end

    Application.put_env(:farm_node, :http_client, ClientSuccess)

    opts = [
      hub_address: "https://hub",
      provisioning_key: "k",
      farm_identifier: "f",
      skip_confirmation: true
    ]

    assert :ok = CLI.run(opts)

    Application.delete_env(:farm_node, :http_client)
  end
end
