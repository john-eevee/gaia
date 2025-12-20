defmodule Gaia.FarmNode.Device.GpsTrackerTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.Device.TelemetryStream
  alias Gaia.FarmNode.Device.GpsTracker

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "gps tracker broadcasts location and battery" do
    TelemetryStream.subscribe("telemetry:gps_tracker")

    {:ok, _} = GpsTracker.start_link(id: "gps-1", interval: 50, battery: 88)

    assert_receive {:telemetry, "telemetry:gps_tracker", payload}, 500

    assert payload.id == "gps-1"
    assert payload.type == :gps_tracker
    assert is_map(payload.location)
    assert is_float(payload.location.lat)
    assert is_float(payload.location.lon)
    assert is_integer(payload.battery) and payload.battery <= 88 and payload.battery >= 0
    assert %DateTime{} = payload.timestamp
  end
end
