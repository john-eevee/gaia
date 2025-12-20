defmodule Gaia.FarmNode.HubConnection.ProvisioningTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  setup do
    Application.ensure_all_started(:farm_node)
    Storage.revoke_credentials()
    :ok
  end

  test "provisioned? and status reflect storage state" do
    assert Provisioning.provisioned?() == false
    assert Provisioning.status() == :unprovisioned

    Storage.store_credentials("DUMMY", "DUMMY")

    assert Provisioning.provisioned?() == true
    assert Provisioning.status() == :active

    Storage.revoke_credentials()
  end

  test "provision succeeds when client returns valid certificate" do
    # Build a self-signed certificate using X509 library
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=test-farm")
    pem = X509.Certificate.to_pem(cert)

    # Test HTTP client that returns the PEM when any CSR is sent
    test_client = %{
      post: fn _url, opts ->
        with {:ok, body} <- Jason.decode(opts[:body]),
             do: {:ok, %{status: 200, body: %{"certificate" => pem}}}
      end
    }

    # Inject a simple module-compatible client
    Application.put_env(:farm_node, :http_client, %{post: test_client.post})

    assert :ok = Provisioning.provision("https://hub", "key", "farm-test")
    assert Storage.provisioned?() == true

    Storage.revoke_credentials()
    Application.delete_env(:farm_node, :http_client)
  end

  test "provision fails when returned certificate is invalid" do
    # Test HTTP client that returns a bad certificate
    test_client = %{
      post: fn _url, _opts -> {:ok, %{status: 200, body: %{"certificate" => "NOT_A_PEM"}}} end
    }

    Application.put_env(:farm_node, :http_client, %{post: test_client.post})

    assert {:error, {:storage_failed, :invalid_certificate_format}} =
             Provisioning.provision("https://hub", "key", "farm-test")

    Application.delete_env(:farm_node, :http_client)
  end
end
