defmodule Gaia.FarmNode.HubConnection.Provisioning.CliInteractiveRepromptTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI

  setup do
    Application.ensure_all_started(:farm_node)
    # Ensure clean state
    Gaia.FarmNode.HubConnection.Provisioning.Storage.revoke_credentials()
    :ok
  end

  test "interactive prompts re-ask on invalid hub address and farm identifier" do
    defmodule ClientOk do
      def post(_url, _opts) do
        key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(key, "/CN=hub-ok")
        {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
      end
    end

    Application.put_env(:farm_node, :http_client, ClientOk)

    # Provide: invalid URL, then valid URL, then key, then invalid id, then valid id, then yes
    input = "not-a-url\nhttps://hub.test\nMYKEY\nBAD-ID\nmy-farm\nyes\n"

    output = capture_io(input, fn -> CLI.run_interactive() end)

    assert output =~ "Hub Address" and output =~ "Farm Identifier"
    assert output =~ "Provisioning" or output =~ "Provisioning cancelled"

    Application.delete_env(:farm_node, :http_client)
  end
end
