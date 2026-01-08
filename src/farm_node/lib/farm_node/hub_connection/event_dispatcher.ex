defmodule Gaia.FarmNode.HubConnection.EventDispatcher do
  @moduledoc """
  Dispatches hub-facing events and device telemetry for batching and forwarding to the Hub.

  This module listens for local EventStream messages and batches them for
  outbound dispatch to the Hub. The buffering mechanism is implemented to
  batch events before dispatching and can be configured via application settings:

    - `:buffer_size` - Maximum number of events to buffer before flushing (default: 10)
    - `:flush_interval` - Time interval (in milliseconds) to flush the buffer (default: 5000)
    - `:subscriptions` - List of EventStream topics to subscribe to. Defaults to
      ["telemetry:all", "event:all"] so the dispatcher receives device telemetry
      and hub-facing local events.

  ## Configuration
      config :farm_node, :event_dispatcher,
        buffer_size: 20,
        flush_interval: 10_000,
        subscriptions: ["telemetry:all", "event:all"]
  """

  use GenServer
  require Logger

  alias Gaia.FarmNode.EventStream

  @default_buffer_size 10
  @default_flush_interval 5_000

  ## Client API

  @doc """
  Starts the EventDispatcher.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Subscribe to configured topics so we capture device telemetry and
    # hub-facing events. Registry keys are exact matches; subscribe to all
    # configured topics.
    topics = subscribed_topics()

    Enum.each(topics, fn topic ->
      {:ok, _} = EventStream.subscribe(topic)
    end)

    Logger.info("EventDispatcher started and subscribed to " <> Enum.join(topics, ", "))

    {:ok, %{buffer: [], size: 0}, {:continue, :schedule_flush}}
  end

  @impl true
  def handle_info({:event, topic, payload}, state) do
    # Handle inbound hub-facing events
    handle_incoming_event(topic, payload, state)
  end

  @impl true
  def handle_info({:telemetry, topic, payload}, state) do
    # Handle inbound device telemetry
    handle_incoming_event(topic, payload, state)
  end

  defp handle_incoming_event(topic, payload, state) do
    # Normalize envelope into {topic, payload} so flush gets both pieces
    state = add_event({topic, payload}, state)
    {:noreply, state, {:continue, {:flush_buffer, :if_full}}}
  end

  @impl true
  def handle_info({:flush_buffer, :scheduled}, state) do
    if state.size > 0 do
      flush(state.buffer)
      {:noreply, %{state | buffer: [], size: 0}, {:continue, :schedule_flush}}
    else
      {:noreply, state, {:continue, :schedule_flush}}
    end
  end

  def handle_info({:flush_buffer, :if_full}, state) do
    handle_flush_if_full(state)
  end

  @impl true
  def handle_continue({:flush_buffer, :if_full}, state) do
    handle_flush_if_full(state)
  end

  defp handle_flush_if_full(state) do
    if state.size >= max_buffer_size() do
      flush(state.buffer)
      {:noreply, %{state | buffer: [], size: 0}, {:continue, :schedule_flush}}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_continue(:schedule_flush, state) do
    schedule_flush()
    {:noreply, state}
  end

  defp schedule_flush do
    Process.send_after(self(), {:flush_buffer, :scheduled}, buffer_flush_interval())
  end

  defp add_event(event, state) do
    new_buffer = [event | state.buffer]
    new_size = state.size + 1
    %{state | buffer: new_buffer, size: new_size}
  end

  defp flush(events) do
    # Send events to Hub
    _events = Enum.reverse(events)
    :ok
  end

  @impl true
  def terminate(reason, state) do
    Logger.info("EventDispatcher terminating: #{inspect(reason)}")
    flush(state.buffer)
    :ok
  end

  defp max_buffer_size do
    Keyword.get(config(), :buffer_size, @default_buffer_size)
  end

  defp buffer_flush_interval do
    Keyword.get(config(), :flush_interval, @default_flush_interval)
  end

  defp subscribed_topics do
    Keyword.get(config(), :subscriptions, ["telemetry:all", "event:all"])
  end

  defp config do
    Application.get_env(:farm_node, :event_dispatcher,
      buffer_size: @default_buffer_size,
      flush_interval: @default_flush_interval,
      subscriptions: ["telemetry:all", "event:all"]
    )
  end

  # notes:
  # we may lose events on crash
end
