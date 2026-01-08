defmodule Gaia.FarmNode.Device.SupervisorTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.Device.Supervisor
  alias Gaia.FarmNode.Device.TempSensor
  alias Gaia.FarmNode.EventStream

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "start_device with explicit module" do
    # Supervisor is started by the application; starting again may return
    # {:error, {:already_started, pid}}. We don't require start_link here.

    EventStream.subscribe("telemetry:temperature_sensor")

    assert {:ok, _pid} =
             Supervisor.start_device(
               module: TempSensor,
               id: "sup-temp-1",
               interval: 50,
               battery: 55
             )

    assert_receive {:telemetry, "telemetry:temperature_sensor", payload}, 500
    assert payload.id == "sup-temp-1"
  end
end
