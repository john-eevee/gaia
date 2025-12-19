defmodule Gaia.FarmNode.Device do
  @moduledoc """
  GenServer that simulates a device producing periodic telemetry and status
  updates. It emits messages via `Gaia.FarmNode.Device.TelemetryStream.broadcast/2`.

  Options:
    - :id - unique id for the device (required)
    - :type - device type atom (required)
    - :interval - telemetry interval ms (default 5_000)
    - :battery - starting battery percent (default 100)
  """

  use GenServer
  require Logger
  alias Gaia.FarmNode.Device.TelemetryStream

  @default_interval 5_000

  defmodule State do
    defstruct [:id, :type, :interval, :battery, :status, :timer_ref]
  end

  # Public API
  def start_link(opts) do
    id = Keyword.fetch!(opts, :id)
    GenServer.start_link(__MODULE__, opts, name: via_name(id))
  end

  def via_name(id), do: {:via, Registry, {Gaia.FarmNode.Device.Registry, id}}

  def status(id) do
    GenServer.call(via_name(id), :status)
  end

  def stop(id) do
    GenServer.stop(via_name(id))
  end

  # GenServer
  @impl true
  def init(opts) do
    id = Keyword.fetch!(opts, :id)
    type = Keyword.fetch!(opts, :type)
    interval = Keyword.get(opts, :interval, @default_interval)
    battery = Keyword.get(opts, :battery, 100)

    state = %State{
      id: id,
      type: type,
      interval: interval,
      battery: battery,
      status: :online,
      timer_ref: schedule_tick(interval)
    }

    Logger.info("Starting simulated device #{id} (#{type})")

    {:ok, state}
  end

  @impl true
  def handle_info(:tick, %State{} = state) do
    # Possibly change status randomly
    state = maybe_flip_offline(state)

    # Simulate battery drain
    battery = max(state.battery - Enum.random(0..3), 0)
    state = %{state | battery: battery}

    # If battery low, set status
    if battery < 20 and state.status != :low_battery do
      state = %{state | status: :low_battery}
      TelemetryStream.broadcast("device_status", %{id: state.id, status: :low_battery, battery: battery})
    end

    # Broadcast telemetry according to device type
    telemetry = generate_telemetry(state)
    TelemetryStream.broadcast("telemetry:#{state.type}", telemetry)
    TelemetryStream.broadcast("telemetry:all", telemetry)

    # Always broadcast device status
    TelemetryStream.broadcast("device_status", %{id: state.id, status: state.status, battery: battery})

    # Schedule next
    ref = schedule_tick(state.interval)
    {:noreply, %{state | timer_ref: ref}}
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, %{id: state.id, status: state.status, battery: state.battery}, state}
  end

  defp schedule_tick(ms), do: Process.send_after(self(), :tick, ms)

  defp maybe_flip_offline(state) do
    case state.status do
      :offline ->
        # small chance to come back online
        if :rand.uniform() < 0.2 do
          %{state | status: :online}
        else
          state
        end

      :online ->
        # small chance to go offline
        if :rand.uniform() < 0.05 do
          %{state | status: :offline}
        else
          state
        end

      :low_battery ->
        if state.battery == 0 do
          %{state | status: :offline}
        else
          state
        end
    end
  end

  defp generate_telemetry(%State{id: id, type: :temperature_sensor} = state) do
    %{
      id: id,
      type: :temperature_sensor,
      timestamp: DateTime.utc_now(),
      temperature: :rand.uniform() * 20 + 5,
      battery: state.battery
    }
  end

  defp generate_telemetry(%State{id: id, type: :pest_detector} = state) do
    %{
      id: id,
      type: :pest_detector,
      timestamp: DateTime.utc_now(),
      pest_detected: :rand.uniform() < 0.1,
      battery: state.battery
    }
  end

  defp generate_telemetry(%State{id: id, type: :moisture_sensor} = state) do
    %{
      id: id,
      type: :moisture_sensor,
      timestamp: DateTime.utc_now(),
      moisture: :rand.uniform() * 100,
      battery: state.battery
    }
  end

  defp generate_telemetry(%State{id: id, type: :gps_tracker} = state) do
    %{
      id: id,
      type: :gps_tracker,
      timestamp: DateTime.utc_now(),
      location: %{lat: 35.0 + :rand.uniform(), lon: -120.0 - :rand.uniform()},
      battery: state.battery
    }
  end

  defp generate_telemetry(%State{id: id, type: type} = state) do
    %{
      id: id,
      type: type,
      timestamp: DateTime.utc_now(),
      battery: state.battery
    }
  end
end
