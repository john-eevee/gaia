defmodule Gaia.FarmNode.HubConnection.EventDispatcherTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.EventDispatcher
  alias Gaia.FarmNode.EventStream

  setup do
    # Ensure the application (and the EventStream registry) is running
    {:ok, _} = Application.ensure_all_started(:farm_node)

    # Preserve & restore the original config to avoid cross-test pollution
    original = Application.get_env(:farm_node, :event_dispatcher)

    on_exit(fn ->
      Application.put_env(:farm_node, :event_dispatcher, original)
    end)

    :ok
  end

  test "subscribes to the configured topic on init" do
    # Configure dispatcher to subscribe to an isolated topic and start it
    Application.put_env(:farm_node, :event_dispatcher, subscriptions: ["telemetry:init_test"])
    start_supervised!({EventDispatcher, []})

    # Registry should have an entry for the subscribed topic
    entries = Registry.lookup(Gaia.FarmNode.EventStream, "telemetry:init_test")
    assert entries != []
  end

  test "buffers incoming {:event, event} messages and increases size" do
    Application.put_env(:farm_node, :event_dispatcher,
      buffer_size: 10,
      flush_interval: 100_000,
      subscriptions: ["telemetry:buffer_test"]
    )

    {:ok, pid} = start_supervised({EventDispatcher, []})

    EventStream.broadcast("telemetry:buffer_test", :one)
    EventStream.broadcast("telemetry:buffer_test", :two)

    # allow the messages to be processed
    Process.sleep(20)

    state = :sys.get_state(pid)
    assert state.size == 2
    # buffer is prepended on each add (latest at head)
    assert state.buffer == [{"telemetry:buffer_test", :two}, {"telemetry:buffer_test", :one}]
  end

  test "flushes and empties buffer on scheduled flush when non-empty" do
    Application.put_env(:farm_node, :event_dispatcher,
      buffer_size: 10,
      flush_interval: 100_000,
      subscriptions: ["telemetry:scheduled_test"]
    )

    {:ok, pid} = start_supervised({EventDispatcher, []})

    EventStream.broadcast("telemetry:scheduled_test", :a)
    EventStream.broadcast("telemetry:scheduled_test", :b)
    Process.sleep(20)

    send(pid, {:flush_buffer, :scheduled})
    Process.sleep(20)

    state = :sys.get_state(pid)

    # The scheduled flush should remove the specific events we just sent
    refute Enum.member?(state.buffer, {"telemetry:scheduled_test", :a})
    refute Enum.member?(state.buffer, {"telemetry:scheduled_test", :b})
  end

  test "flushes buffer when if_full message and buffer is at or above max size" do
    Application.put_env(:farm_node, :event_dispatcher,
      buffer_size: 2,
      flush_interval: 100_000,
      subscriptions: ["telemetry:if_full_test"]
    )

    {:ok, pid} = start_supervised({EventDispatcher, []})

    EventStream.broadcast("telemetry:if_full_test", :x)
    EventStream.broadcast("telemetry:if_full_test", :y)
    Process.sleep(20)

    # simulate the 'if_full' check
    send(pid, {:flush_buffer, :if_full})
    Process.sleep(20)

    state = :sys.get_state(pid)

    # After an if_full flush the items we added should no longer be present
    refute Enum.member?(state.buffer, {"telemetry:if_full_test", :x})
    refute Enum.member?(state.buffer, {"telemetry:if_full_test", :y})
  end

  test "terminate stops the dispatcher process" do
    Application.put_env(:farm_node, :event_dispatcher,
      buffer_size: 10,
      flush_interval: 100_000,
      subscriptions: ["telemetry:terminate_test"]
    )

    {:ok, pid} = start_supervised({EventDispatcher, []})

    # Generate some buffered work
    EventStream.broadcast("telemetry:terminate_test", :will_flush_on_terminate)
    Process.sleep(20)

    # stop the supervised child; terminate/2 should run
    stop_supervised(EventDispatcher)
    Process.sleep(20)

    refute Process.alive?(pid)
  end
end
