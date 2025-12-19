defmodule Gaia.FarmNode.HubConnection.Provisioning.StorageTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  @test_ssl_dir "priv/test_ssl"
  @test_cert "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
  @test_key "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"

  setup do
    # Override the SSL directory for tests
    original_ssl_dir = Application.get_env(:farm_node, :ssl_dir, "priv/ssl")
    Application.put_env(:farm_node, :ssl_dir, @test_ssl_dir)

    # Clean up test directory before each test
    File.rm_rf(@test_ssl_dir)

    on_exit(fn ->
      File.rm_rf(@test_ssl_dir)
      Application.put_env(:farm_node, :ssl_dir, original_ssl_dir)
    end)

    :ok
  end

  describe "provisioned?/0" do
    test "returns false when no credentials exist" do
      refute Storage.provisioned?()
    end

    test "returns true when credentials exist" do
      # Store credentials
      :ok = Storage.store_credentials(@test_cert, @test_key)

      assert Storage.provisioned?()
    end

    test "returns false if only certificate exists" do
      File.mkdir_p!(@test_ssl_dir)
      File.write!(Path.join(@test_ssl_dir, "farm_node_cert.pem"), @test_cert)

      refute Storage.provisioned?()
    end

    test "returns false if only key exists" do
      File.mkdir_p!(@test_ssl_dir)
      File.write!(Path.join(@test_ssl_dir, "farm_node_key.pem"), @test_key)

      refute Storage.provisioned?()
    end
  end

  describe "store_credentials/2" do
    test "stores certificate and key successfully" do
      assert :ok = Storage.store_credentials(@test_cert, @test_key)

      # Verify files exist
      assert File.exists?(Path.join(@test_ssl_dir, "farm_node_cert.pem"))
      assert File.exists?(Path.join(@test_ssl_dir, "farm_node_key.pem"))
      assert File.exists?(Path.join(@test_ssl_dir, "provisioning_state.json"))
    end

    test "creates directory if it doesn't exist" do
      refute File.exists?(@test_ssl_dir)

      assert :ok = Storage.store_credentials(@test_cert, @test_key)

      assert File.dir?(@test_ssl_dir)
    end

    test "stored certificate matches input" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      stored_cert = File.read!(Path.join(@test_ssl_dir, "farm_node_cert.pem"))
      assert stored_cert == @test_cert
    end

    test "stored key matches input" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      stored_key = File.read!(Path.join(@test_ssl_dir, "farm_node_key.pem"))
      assert stored_key == @test_key
    end

    test "creates provisioning state file with timestamp" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      state_path = Path.join(@test_ssl_dir, "provisioning_state.json")
      {:ok, json} = File.read(state_path)
      {:ok, state} = Jason.decode(json)

      assert state["status"] == "active"
      assert state["provisioned_at"]
    end
  end

  describe "get_credential_paths/0" do
    test "returns paths when provisioned" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      assert {:ok, %{cert: cert_path, key: key_path}} =
               Storage.get_credential_paths()

      assert String.ends_with?(cert_path, "farm_node_cert.pem")
      assert String.ends_with?(key_path, "farm_node_key.pem")
    end

    test "returns error when not provisioned" do
      assert {:error, :not_provisioned} = Storage.get_credential_paths()
    end
  end

  describe "load_credentials/0" do
    test "loads certificate and key when provisioned" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      assert {:ok, %{cert: cert, key: key}} = Storage.load_credentials()

      assert cert == @test_cert
      assert key == @test_key
    end

    test "returns error when not provisioned" do
      assert {:error, :not_provisioned} = Storage.load_credentials()
    end
  end

  describe "revoke_credentials/0" do
    test "removes all credential files" do
      :ok = Storage.store_credentials(@test_cert, @test_key)

      assert Storage.provisioned?()

      :ok = Storage.revoke_credentials()

      refute Storage.provisioned?()
      refute File.exists?(Path.join(@test_ssl_dir, "farm_node_cert.pem"))
      refute File.exists?(Path.join(@test_ssl_dir, "farm_node_key.pem"))
      refute File.exists?(Path.join(@test_ssl_dir, "provisioning_state.json"))
    end

    test "succeeds even when files don't exist" do
      refute Storage.provisioned?()

      assert :ok = Storage.revoke_credentials()
    end
  end
end
