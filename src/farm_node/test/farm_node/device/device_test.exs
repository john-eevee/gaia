defmodule Gaia.FarmNode.DeviceTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.Device.PestDetector
  alias Gaia.FarmNode.EventStream

  setup do
    # Ensure supervisor and registry are running
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "device broadcasts telemetry and status" do
    {:ok, _pid} = PestDetector.start_link(id: "dev-1", interval: 50, battery: 50)

    EventStream.subscribe("telemetry:pest_detector")
    EventStream.subscribe("device_status")

    assert_receive {:telemetry, "telemetry:pest_detector", payload}, 200
    assert payload.type == :pest_detector
    assert Map.has_key?(payload, :pest_detected)

    assert_receive {:event, "device_status", %{id: "dev-1", status: status, battery: battery}},
                   200

    assert status in [:online, :offline, :low_battery]
    assert is_integer(battery)
  end
end
