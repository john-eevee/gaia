defmodule Gaia.Device.CustomDeviceTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.EventStream

  defmodule CustomDevice do
    use Gaia.Device, type: :custom_sensor

    @impl Gaia.Device
    def generate_telemetry(state) do
      %{
        custom_field: "custom_value",
        battery_level: state.battery,
        reading: :rand.uniform() * 42
      }
    end
  end

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "custom device generates custom events" do
    EventStream.subscribe("telemetry:custom_sensor")

    {:ok, _} = CustomDevice.start_link(id: "custom-1", interval: 50, battery: 75)

    assert_receive {:telemetry, "telemetry:custom_sensor", payload}, 500

    # Standard fields added by macro
    assert payload.type == :custom_sensor
    assert payload.id == "custom-1"
    # Battery may drain slightly between start and first tick
    assert payload.battery <= 75
    assert payload.battery >= 72
    assert %DateTime{} = payload.timestamp

    # Custom fields from generate_telemetry/1
    assert payload.custom_field == "custom_value"
    # battery_level reflects the state at tick time (may have drained)
    assert payload.battery_level <= 75
    assert payload.battery_level >= 72
    assert is_float(payload.reading)
  end

  test "device can be stopped" do
    {:ok, _} = CustomDevice.start_link(id: "stoppable-1", interval: 50)
    assert :ok = CustomDevice.stop("stoppable-1")
  end

  test "device status can be queried" do
    {:ok, _} = CustomDevice.start_link(id: "query-1", interval: 50, battery: 80)
    status = CustomDevice.status("query-1")

    assert status.id == "query-1"
    assert status.battery == 80
    assert status.status in [:online, :offline, :low_battery]
  end
end
