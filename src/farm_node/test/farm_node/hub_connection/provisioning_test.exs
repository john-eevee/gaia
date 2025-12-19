defmodule Gaia.FarmNode.HubConnection.ProvisioningTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning

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

    # Note: Full integration test would require mocking the HTTP client
    # which is better done with a proper HTTP mocking library in a real scenario
  end
end
