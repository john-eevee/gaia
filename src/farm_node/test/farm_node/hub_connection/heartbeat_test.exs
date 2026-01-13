defmodule Gaia.FarmNode.HubConnection.HeartbeatTest do
  alias Gaia.FarmNode.HubConnection.Heartbeat
  use ExUnit.Case, async: false

  @test_ssl_dir "test/tmp/ssl_heartbeat"

  defmodule MockHttpClient do
    def request(_opts), do: {:ok, %{status: 200}}
  end

  setup do
    # Preserve original configuration
    original_client = Application.get_env(:farm_node, :http_client)
    original_ssl_dir = Application.get_env(:farm_node, :ssl_dir)

    # Prepare a dummy SSL directory with valid-ish credentials to satisfy
    # Client.connection_opts/0 which is called during heartbeat.
    File.mkdir_p!(@test_ssl_dir)
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=test")
    File.write!(Path.join(@test_ssl_dir, "cert.pem"), X509.Certificate.to_pem(cert))
    File.write!(Path.join(@test_ssl_dir, "key.pem"), X509.PrivateKey.to_pem(key))

    # Mock the HTTP client to avoid real network calls and ensure validation passes
    Application.put_env(:farm_node, :http_client, MockHttpClient)
    Application.put_env(:farm_node, :ssl_dir, @test_ssl_dir)

    on_exit(fn ->
      File.rm_rf!(@test_ssl_dir)

      if original_client do
        Application.put_env(:farm_node, :http_client, original_client)
      else
        Application.delete_env(:farm_node, :http_client)
      end

      if original_ssl_dir do
        Application.put_env(:farm_node, :ssl_dir, original_ssl_dir)
      else
        Application.delete_env(:farm_node, :ssl_dir)
      end
    end)

    :ok
  end

  describe "Heartbeat Server" do
    test "should initialize without args" do
      {:ok, pid} = Heartbeat.start_link(name: :hbt_1)

      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "defaults should match expected" do
      {:ok, pid} = Heartbeat.start_link()
      state = :sys.get_state(pid)

      assert state.interval == :timer.minutes(5)
      assert state.timeout == :timer.seconds(30)
      assert pid == Process.whereis(Heartbeat)
    end

    test "should schedule a timer" do
      {:ok, pid} = Heartbeat.start_link(interval: 1_000, name: :hbt_3)
      state = :sys.get_state(pid)
      assert is_reference(state.timer_ref)
      Process.exit(pid, :normal)
    end

    test "should update the reference when rescheduling" do
      {:ok, pid} = Heartbeat.start_link(interval: 1_000, name: :hbt_4)
      state = :sys.get_state(pid)
      ref = state.timer_ref

      send(pid, :beat)
      Process.sleep(10)
      new_state = :sys.get_state(pid)
      assert is_reference(new_state.timer_ref)
      refute new_state.timer_ref == ref
      Process.exit(pid, :normal)
    end
  end
end
