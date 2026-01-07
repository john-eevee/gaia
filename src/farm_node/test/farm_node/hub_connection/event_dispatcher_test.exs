defmodule Gaia.FarmNode.HubConnection.EventDispatcherTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.HubConnection.EventDispatcher

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
    # Start dispatcher with default config
    start_supervised!({EventDispatcher, []})

    # Registry should have an entry for the subscribed topic
    entries = Registry.lookup(Gaia.FarmNode.EventStream, "farm:*")
    assert entries != []
  end

  test "buffers incoming {:event, event} messages and increases size" do
    Application.put_env(:farm_node, :event_dispatcher, buffer_size: 10, flush_interval: 100_000)
    {:ok, pid} = start_supervised({EventDispatcher, []})

    send(pid, {:event, :one})
    send(pid, {:event, :two})

    # allow the messages to be processed
    Process.sleep(20)

    state = :sys.get_state(pid)
    assert state.size == 2
    # buffer is prepended on each add (latest at head)
    assert state.buffer == [:two, :one]
  end

  test "flushes and empties buffer on scheduled flush when non-empty" do
    Application.put_env(:farm_node, :event_dispatcher, buffer_size: 10, flush_interval: 100_000)
    {:ok, pid} = start_supervised({EventDispatcher, []})

    send(pid, {:event, :a})
    send(pid, {:event, :b})
    Process.sleep(20)

    send(pid, {:flush_buffer, :scheduled})
    Process.sleep(20)

    state = :sys.get_state(pid)
    assert state.size == 0
    assert state.buffer == []
  end

  test "flushes buffer when if_full message and buffer is at or above max size" do
    Application.put_env(:farm_node, :event_dispatcher, buffer_size: 2, flush_interval: 100_000)
    {:ok, pid} = start_supervised({EventDispatcher, []})

    send(pid, {:event, :x})
    send(pid, {:event, :y})
    Process.sleep(20)

    # simulate the 'if_full' check
    send(pid, {:flush_buffer, :if_full})
    Process.sleep(20)

    state = :sys.get_state(pid)
    assert state.size == 0
    assert state.buffer == []
  end

  test "terminate stops the dispatcher process" do
    Application.put_env(:farm_node, :event_dispatcher, buffer_size: 10, flush_interval: 100_000)
    {:ok, pid} = start_supervised({EventDispatcher, []})

    # Generate some buffered work
    send(pid, {:event, :will_flush_on_terminate})
    Process.sleep(20)

    # stop the supervised child; terminate/2 should run
    stop_supervised(EventDispatcher)

    # assert the process is no longer alive
    refute Process.alive?(pid)
  end
end
