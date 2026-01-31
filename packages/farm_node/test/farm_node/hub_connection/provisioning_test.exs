defmodule Gaia.FarmNode.HubConnection.ProvisioningTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  @test_ssl_dir "priv/test_ssl_provisioning"

  setup do
    # Override the SSL directory for tests
    Application.put_env(:farm_node, :ssl_dir, @test_ssl_dir)

    # Clean up test directory before each test
    File.rm_rf(@test_ssl_dir)

    on_exit(fn ->
      File.rm_rf(@test_ssl_dir)
    end)

    :ok
  end

  describe "provisioned?/0" do
    test "returns false initially" do
      refute Provisioning.provisioned?()
    end
  end

  describe "status/0" do
    test "returns :unprovisioned when no credentials exist" do
      assert :unprovisioned = Provisioning.status()
    end

    test "returns :active when credentials exist" do
      # Manually create credentials
      File.mkdir_p!(@test_ssl_dir)
      File.write!(Path.join(@test_ssl_dir, "farm_node_cert.pem"), "cert")
      File.write!(Path.join(@test_ssl_dir, "farm_node_key.pem"), "key")

      assert :active = Provisioning.status()
    end
  end

  describe "provision/3" do
    test "returns error when already provisioned" do
      # Pre-provision
      File.mkdir_p!(@test_ssl_dir)
      File.write!(Path.join(@test_ssl_dir, "farm_node_cert.pem"), "cert")
      File.write!(Path.join(@test_ssl_dir, "farm_node_key.pem"), "key")

      assert {:error, :already_provisioned} =
               Provisioning.provision("https://hub.test", "key", "farm-1")
    end

    test "successful provisioning stores credentials when hub returns certificate" do
      defmodule TestHttpClientSuccess do
        def post(_url, _opts) do
          key = X509.PrivateKey.new_rsa(2048)
          cert = X509.Certificate.self_signed(key, "/CN=hub-test")
          {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClientSuccess)

      assert :ok = Provisioning.provision("https://hub", "k", "farm-succ")
      assert Storage.provisioned?() == true

      Storage.revoke_credentials()
      Application.delete_env(:farm_node, :http_client)
    end

    test "provision fails when returned certificate is invalid" do
      defmodule TestHttpClientBad do
        def post(_url, _opts), do: {:ok, %{status: 200, body: %{"certificate" => "NOT_A_PEM"}}}
      end

      Application.put_env(:farm_node, :http_client, TestHttpClientBad)

      assert {:error, {:storage_failed, :invalid_certificate_format}} =
               Provisioning.provision("https://hub", "k", "farm-y")

      Application.delete_env(:farm_node, :http_client)
    end

    # Note: A full integration test with a real Hub would verify the happy path fully
  end
end
