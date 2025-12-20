defmodule Mix.Tasks.FarmNode.StatusTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  setup do
    Application.ensure_all_started(:farm_node)
    Storage.revoke_credentials()
    :ok
  end

  test "status shows unprovisioned" do
    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)
    assert output =~ "UNPROVISIONED"
    assert output =~ "mix farm_node.provision"
  end

  test "status shows active when credentials present" do
    # Write real certificate so parsing succeeds
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=farm-test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Status: ✅ ACTIVE"
    assert output =~ "Credentials Location"
    assert output =~ "Certificate Details" or output =~ "Unable to parse certificate details"

    Storage.revoke_credentials()
  end
end
