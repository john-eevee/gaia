defmodule Gaia.FarmNode.DeviceTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.Device
  alias Gaia.FarmNode.Device.TelemetryStream

  setup do
    # Ensure supervisor and registry are running
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "device broadcasts telemetry and status" do
    {:ok, _pid} = Gaia.FarmNode.Device.Supervisor.start_device(id: "dev-1", type: :pest_detector, interval: 50, battery: 50)

    TelemetryStream.subscribe("telemetry:pest_detector")
    TelemetryStream.subscribe("device_status")

    assert_receive {:telemetry, "telemetry:pest_detector", payload}, 200
    assert payload.type == :pest_detector

    assert_receive {:telemetry, "device_status", %{id: "dev-1", status: status, battery: battery}}, 200
    assert status in [:online, :offline, :low_battery]
    assert is_integer(battery)
  end
end
