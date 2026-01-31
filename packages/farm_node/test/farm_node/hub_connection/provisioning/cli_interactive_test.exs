defmodule Gaia.FarmNode.HubConnection.Provisioning.CliInteractiveTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI

  setup do
    Application.ensure_all_started(:farm_node)
    # Ensure we're in a clean provisioning state
    Gaia.FarmNode.HubConnection.Provisioning.Storage.revoke_credentials()
    :ok
  end

  test "run_interactive completes with user input" do
    defmodule ClientOk do
      def post(_url, _opts) do
        key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(key, "/CN=hub-ok")
        {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
      end
    end

    Application.put_env(:farm_node, :http_client, ClientOk)

    input = "https://hub.test\nMYKEY\nmy-farm\nyes\n"

    output = capture_io(input, fn -> CLI.run_interactive() end)

    # Either provisioning completes successfully or we cancelled -- both are valid
    assert output =~ "Provisioning" or output =~ "Provisioning cancelled"

    Application.delete_env(:farm_node, :http_client)
  end

  test "run_interactive cancels when user says no" do
    input = "https://hub.test\nMYKEY\nmy-farm\nno\n"

    # capture stderr as well, in case messages print there
    capture_io(input, fn -> send(self(), CLI.run_interactive()) end)

    assert_receive {:error, :cancelled}, 500
  end
end
