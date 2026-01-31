defmodule Gaia.FarmNode.HubConnection.HeartbeatTest do
  alias Gaia.FarmNode.HubConnection.Heartbeat
  use ExUnit.Case, async: true
  import Mox

  setup :verify_on_exit!

  setup_all %{} do
    Mox.defmock(MockHubConnectionClient, for: Gaia.FarmNode.HubConnection.Client)
    Application.put_env(:farm_node, Gaia.FarmNode.HubConnection.Client, MockHubConnectionClient)
    :ok
  end

  describe "Heartbeat Server" do
    test "should initialize without args" do
      {:ok, pid} = Heartbeat.start_link()

      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "defaults should match expected" do
      # make sure this is the only one with default name
      {:ok, pid} = Heartbeat.start_link()
      state = :sys.get_state(pid)

      assert state.interval == :timer.minutes(5)
      assert state.timeout == :timer.seconds(30)
      assert pid == Process.whereis(Heartbeat)
    end

    test "should schedule a timer" do
      {:ok, pid} = Heartbeat.start_link(interval: 1_000)
      state = :sys.get_state(pid)
      assert is_reference(state.timer_ref)
      Process.exit(pid, :normal)
    end

    test "should update the reference when rescheduling" do
      Mox.expect(MockHubConnectionClient, :heartbeat, fn -> {:ok, Req.Response.new()} end)
      {:ok, pid} = Heartbeat.start_link(interval: 1_000)
      # Allow the server to use the stub and mocks
      allow(MockHubConnectionClient, self(), pid)
      state = :sys.get_state(pid)
      ref = state.timer_ref

      send(pid, :beat)
      Process.sleep(100)
      new_state = :sys.get_state(pid)
      assert is_reference(new_state.timer_ref)
      refute new_state.timer_ref == ref
      Process.exit(pid, :normal)
    end
  end
end
