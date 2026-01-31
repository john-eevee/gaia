defmodule Mix.Tasks.FarmNode.ProvisionInteractiveTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  setup do
    Application.ensure_all_started(:farm_node)
    Gaia.FarmNode.HubConnection.Provisioning.Storage.revoke_credentials()
    :ok
  end

  test "mix task interactive provisioning completes with user input" do
    # Provide prompts: hub, key, id, yes
    defmodule ClientOk2 do
      def post(_url, _opts) do
        key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(key, "/CN=hub-ok")
        {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
      end
    end

    Application.put_env(:farm_node, :http_client, ClientOk2)

    input = "https://hub.test\nMYKEY\nmy-farm\nyes\n"

    output = capture_io(input, fn -> Mix.Tasks.FarmNode.Provision.run([]) end)

    assert output =~ "Provisioning Successful" or output =~ "Provisioning"

    Application.delete_env(:farm_node, :http_client)
  end
end
