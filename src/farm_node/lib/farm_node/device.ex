defmodule Gaia.Device do
  @moduledoc """
  Behaviour and macro to define simulated IoT devices.

  When you `use Gaia.Device`, you get a GenServer that:
  - Schedules periodic telemetry broadcasts
  - Manages device status (online/offline/low_battery)
  - Simulates battery drain
  - Broadcasts telemetry via TelemetryStream

  ## Example

      defmodule MyApp.TempSensor do
        use Gaia.Device, type: :temperature_sensor

        @impl Gaia.Device
        def generate_telemetry(state) do
          %{
            temperature: :rand.uniform() * 20 + 5,
            humidity: :rand.uniform() * 100
          }
        end
      end

      # Start the device
      {:ok, pid} = MyApp.TempSensor.start_link(id: "sensor-1", interval: 1000)

  ## Callbacks

  You must implement `generate_telemetry/1` which receives the device state
  and returns a map of telemetry data to broadcast.
  """

  @doc """
  Generate telemetry data for this device.

  Receives the device state struct and should return a map of telemetry data.
  The returned map will be merged with standard fields (id, type, timestamp, battery).
  """
  @callback generate_telemetry(state :: map()) :: map()

  defmacro __using__(opts) do
    type = Keyword.fetch!(opts, :type)

    quote location: :keep do
      use GenServer
      require Logger
      alias Gaia.FarmNode.Device.TelemetryStream

      @behaviour Gaia.Device
      @device_type unquote(type)
      @default_interval 5_000

      defmodule State do
        defstruct [:id, :type, :interval, :battery, :status, :timer_ref]
      end

      # Public API
      def start_link(opts) when is_list(opts) do
        id = Keyword.fetch!(opts, :id)
        opts = Keyword.put_new(opts, :type, @device_type)
        GenServer.start_link(__MODULE__, opts, name: via_name(id))
      end

      def via_name(id), do: {:via, Registry, {Gaia.FarmNode.Device.Registry, id}}

      def status(id) do
        GenServer.call(via_name(id), :status)
      end

      def stop(id) do
        GenServer.stop(via_name(id))
      end

      def child_spec(opts) do
        %{
          id: opts[:id] || __MODULE__,
          start: {__MODULE__, :start_link, [opts]},
          restart: :transient
        }
      end

      # GenServer callbacks
      @impl true
      def init(opts) do
        id = Keyword.fetch!(opts, :id)
        type = Keyword.get(opts, :type, @device_type)
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

          TelemetryStream.broadcast("device_status", %{
            id: state.id,
            status: :low_battery,
            battery: battery
          })
        end

        # Generate custom telemetry data
        custom_data = generate_telemetry(state)

        # Merge with standard fields
        telemetry =
          Map.merge(custom_data, %{
            id: state.id,
            type: state.type,
            timestamp: DateTime.utc_now(),
            battery: state.battery
          })

        # Broadcast telemetry
        TelemetryStream.broadcast("telemetry:#{state.type}", telemetry)
        TelemetryStream.broadcast("telemetry:all", telemetry)

        # Always broadcast device status
        TelemetryStream.broadcast("device_status", %{
          id: state.id,
          status: state.status,
          battery: battery
        })

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

      # Default implementation - can be overridden
      @impl Gaia.Device
      def generate_telemetry(_state) do
        %{}
      end

      defoverridable generate_telemetry: 1
    end
  end
end
