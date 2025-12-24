defmodule Gaia.FarmNode.Device.MoistureSensorTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.EventStream
  alias Gaia.FarmNode.Device.MoistureSensor

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "moisture sensor broadcasts moisture" do
    EventStream.subscribe("telemetry:moisture_sensor")

    {:ok, _} = MoistureSensor.start_link(id: "moist-1", interval: 50, battery: 66)

    assert_receive {:telemetry, "telemetry:moisture_sensor", payload}, 500

    assert payload.id == "moist-1"
    assert payload.type == :moisture_sensor
    assert is_float(payload.moisture)
    assert is_integer(payload.battery) and payload.battery <= 66 and payload.battery >= 0
  end
end
