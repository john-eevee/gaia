defmodule Gaia.FarmNode.HubConnection.EventDispatcher do
  @moduledoc """
  Dispatches events received from the Hub to local subscribers.

  This module listens for events from the Hub connection and forwards them
  to interested local processes via the EventStream.

  The buffering mechanism is implemented to batch events before dispatching,
  and it can be configured via application settings:

    - `:buffer_size` - Maximum number of events to buffer
    before flushing (default: 10)
    - `:flush_interval` - Time interval (in milliseconds)
    to flush the buffer (default: 5000)

  ## Configuration
      config :farm_node, :event_dispatcher
        buffer_size: 20,
        flush_interval: 10_000
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
    # Subscribe to Hub events
    {:ok, _} = EventStream.subscribe("farm:*")
    Logger.info("EventDispatcher started and subscribed to Hub events")

    {:ok, %{buffer: [], size: 0}}
  end

  @impl true
  def handle_info({:event, event}, state) do
    state = add_event(event, state)
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

  defp config do
    Application.get_env(:farm_node, :event_dispatcher,
      buffer_size: @default_buffer_size,
      flush_interval: @default_flush_interval
    )
  end

  # notes:
  # we may lose events on crash
end
