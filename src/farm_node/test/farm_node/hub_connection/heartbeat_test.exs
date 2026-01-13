defmodule Gaia.FarmNode.HubConnection.HeartbeatTest do
  alias Gaia.FarmNode.HubConnection.Heartbeat
  use ExUnit.Case, async: true

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
