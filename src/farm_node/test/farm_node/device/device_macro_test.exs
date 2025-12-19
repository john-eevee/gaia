defmodule Gaia.DeviceMacroTest do
  use ExUnit.Case, async: false

  defmodule TempDevice do
    use Gaia.Device, type: :temperature_sensor
  end

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "can start module-defined device" do
    Gaia.FarmNode.Device.TelemetryStream.subscribe("telemetry:temperature_sensor")
    {:ok, _} = TempDevice.start_link(id: "temp-1", interval: 50, battery: 90)
    assert_receive {:telemetry, "telemetry:temperature_sensor", payload}, 500
    assert payload.type == :temperature_sensor
  end
end
