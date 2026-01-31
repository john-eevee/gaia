defmodule Gaia.FarmNode.TelemetryStorage do
  @moduledoc """
  TelemetryStorage - Subscribes to telemetry events and stores them locally.

  This module's primary responsibility is to receive telemetry from the broker/devices
  and persist it in the local database for future use. It runs in parallel with other
  telemetry consumers like TelemetrySharing and LocalRules.

  Per ADR-006, this module subscribes directly to the telemetry source and handles
  local storage independently of data sharing decisions.
  """

  use GenServer
  require Logger

  alias Gaia.FarmNode.EventStream

  @type telemetry :: map()

  ## Client API

  @doc """
  Starts the TelemetryStorage process.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the current state of the storage (for debugging/testing).
  """
  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Subscribe to device telemetry (incoming device data)
    {:ok, _} = EventStream.subscribe("telemetry:all")
    Logger.info("TelemetryStorage started and subscribed to telemetry:all")

    state = %{
      telemetry_stored: 0,
      last_stored: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:telemetry, _topic, telemetry}, state) do
    # Store the telemetry locally
    new_state = store_telemetry(telemetry, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  ## Private Functions

  # Store telemetry in local database (V1: in-memory state tracking)
  # TODO: In future versions, persist to actual database (Ecto)
  defp store_telemetry(telemetry, state) do
    Logger.debug("TelemetryStorage: Storing telemetry from device #{telemetry[:id]}")

    # Update state to track storage
    %{
      state
      | telemetry_stored: state.telemetry_stored + 1,
        last_stored: telemetry
    }
  end
end
