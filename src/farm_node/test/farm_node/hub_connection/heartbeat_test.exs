defmodule Gaia.FarmNode.HubConnection.HeartbeatTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.Heartbeat
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  @test_ssl_dir "priv/test_ssl_heartbeat"
  @test_hub_address "https://hub.test.local"

  setup do
    # Override the SSL directory and hub address for tests
    Application.put_env(:farm_node, :ssl_dir, @test_ssl_dir)
    Application.put_env(:farm_node, :hub_address, @test_hub_address)

    # Clean up test directory before each test
    File.rm_rf(@test_ssl_dir)

    on_exit(fn ->
      File.rm_rf(@test_ssl_dir)
      Application.delete_env(:farm_node, :http_client)
      Application.delete_env(:farm_node, :ssl_dir)
      Application.delete_env(:farm_node, :hub_address)
    end)

    :ok
  end

  describe "init/1" do
    test "does not start heartbeat when node is not provisioned" do
      {:ok, state} = Heartbeat.init([])

      assert state.hub_address == nil
      assert state.revoked == true
      assert state.timer_ref == nil
    end

    test "does not start heartbeat when hub_address is not configured" do
      create_test_credentials()
      Application.delete_env(:farm_node, :hub_address)

      {:ok, state} = Heartbeat.init([])

      assert state.hub_address == nil
      assert state.revoked == true
      assert state.timer_ref == nil
    end

    test "starts heartbeat when provisioned and hub_address is configured" do
      create_test_credentials()

      {:ok, state} = Heartbeat.init([])

      assert state.hub_address == @test_hub_address
      assert state.revoked == false
      assert is_reference(state.timer_ref)
    end
  end

  describe "heartbeat requests" do
    setup do
      create_test_credentials()
      :ok
    end

    test "successful heartbeat (200 OK)" do
      defmodule TestHttpClient200 do
        def get(_url, _opts) do
          {:ok, %{status: 200}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClient200)

      {:ok, pid} = Heartbeat.start_link([])
      send(pid, :send_heartbeat)

      # Give it time to process
      Process.sleep(100)

      # Should still be running and not revoked
      state = :sys.get_state(pid)
      assert state.revoked == false

      GenServer.stop(pid)
    end

    test "handles 403 Forbidden by marking as revoked" do
      defmodule TestHttpClient403 do
        def get(_url, _opts) do
          {:ok, %{status: 403}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClient403)

      {:ok, pid} = Heartbeat.start_link([])
      send(pid, :send_heartbeat)

      # Give it time to process revocation
      Process.sleep(200)

      # Should be marked as revoked
      state = :sys.get_state(pid)
      assert state.revoked == true
      assert state.timer_ref == nil

      # Credentials should be deleted
      refute Storage.provisioned?()

      GenServer.stop(pid)
    end

    test "handles network errors gracefully (logs and continues)" do
      defmodule TestHttpClientError do
        def get(_url, _opts) do
          {:error, %{reason: :timeout}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClientError)

      {:ok, pid} = Heartbeat.start_link([])
      send(pid, :send_heartbeat)

      # Give it time to process
      Process.sleep(100)

      # Should still be running and not revoked (offline scenario)
      state = :sys.get_state(pid)
      assert state.revoked == false

      GenServer.stop(pid)
    end

    test "handles unexpected status codes" do
      defmodule TestHttpClient500 do
        def get(_url, _opts) do
          {:ok, %{status: 500}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClient500)

      {:ok, pid} = Heartbeat.start_link([])
      send(pid, :send_heartbeat)

      # Give it time to process
      Process.sleep(100)

      # Should still be running and not revoked
      state = :sys.get_state(pid)
      assert state.revoked == false

      GenServer.stop(pid)
    end

    test "does not send heartbeat when already revoked" do
      defmodule TestHttpClientNeverCalled do
        def get(_url, _opts) do
          raise "Should not be called when revoked"
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClientNeverCalled)

      # Start with revoked state
      {:ok, pid} = Heartbeat.start_link([])
      GenServer.cast(pid, :mark_revoked)
      Process.sleep(50)

      # This should not raise because the HTTP client won't be called
      send(pid, :send_heartbeat)
      Process.sleep(100)

      GenServer.stop(pid)
    end
  end

  describe "periodic scheduling" do
    test "schedules next heartbeat after processing" do
      create_test_credentials()

      defmodule TestHttpClientScheduling do
        def get(_url, _opts) do
          {:ok, %{status: 200}}
        end
      end

      Application.put_env(:farm_node, :http_client, TestHttpClientScheduling)

      {:ok, pid} = Heartbeat.start_link([])

      # Get initial timer
      state1 = :sys.get_state(pid)
      initial_timer = state1.timer_ref

      # Trigger heartbeat
      send(pid, :send_heartbeat)
      Process.sleep(100)

      # Should have a new timer scheduled
      state2 = :sys.get_state(pid)
      assert state2.timer_ref != initial_timer
      assert is_reference(state2.timer_ref)

      GenServer.stop(pid)
    end
  end

  # Helper Functions

  defp create_test_credentials do
    # Create test SSL directory and credentials
    File.mkdir_p!(@test_ssl_dir)

    # Generate test certificate and key
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=test-farm-node")

    cert_pem = X509.Certificate.to_pem(cert)
    key_pem = X509.PrivateKey.to_pem(key)

    File.write!(Path.join(@test_ssl_dir, "farm_node_cert.pem"), cert_pem)
    File.write!(Path.join(@test_ssl_dir, "farm_node_key.pem"), key_pem)

    # Create state file
    state = %{
      provisioned_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      status: "active"
    }

    state_json = Jason.encode!(state)
    File.write!(Path.join(@test_ssl_dir, "provisioning_state.json"), state_json)
  end
end
