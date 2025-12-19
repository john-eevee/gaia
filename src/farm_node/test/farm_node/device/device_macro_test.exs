defmodule Gaia.DeviceMacroTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.Device.TempSensor

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "can start module-defined device with custom telemetry" do
    Gaia.FarmNode.Device.TelemetryStream.subscribe("telemetry:temperature_sensor")
    {:ok, _} = TempSensor.start_link(id: "temp-1", interval: 50, battery: 90)
    assert_receive {:telemetry, "telemetry:temperature_sensor", payload}, 500
    assert payload.type == :temperature_sensor
    assert Map.has_key?(payload, :temperature)
    assert is_float(payload.temperature)
  end
end
