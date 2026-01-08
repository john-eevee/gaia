defmodule Gaia.FarmNode.TelemetryStorageTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.TelemetryStorage
  alias Gaia.FarmNode.EventStream

  setup do
    # Ensure the application is started
    Application.ensure_all_started(:farm_node)

    :ok
  end

  describe "TelemetryStorage" do
    test "starts successfully" do
      # The module should be started by the application
      assert Process.whereis(TelemetryStorage) != nil
    end

    test "subscribes to telemetry:all on init" do
      # Verify the module is running and has a state
      state = TelemetryStorage.get_state()
      assert is_map(state)
      assert state.telemetry_stored >= 0
    end

    test "stores telemetry when received" do
      initial_state = TelemetryStorage.get_state()
      initial_count = initial_state.telemetry_stored

      # Broadcast a telemetry event
      telemetry = %{
        id: "test-sensor-1",
        type: :temperature_sensor,
        temperature: 22.5,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry)

      # Give it time to process
      Process.sleep(50)

      # Verify telemetry was stored
      new_state = TelemetryStorage.get_state()
      assert new_state.telemetry_stored == initial_count + 1
      assert new_state.last_stored == telemetry
    end

    test "stores multiple telemetry events" do
      initial_state = TelemetryStorage.get_state()
      initial_count = initial_state.telemetry_stored

      # Broadcast multiple telemetry events
      telemetry_list = [
        %{id: "sensor-1", type: :temperature_sensor, temperature: 20.0, battery: 100},
        %{id: "sensor-2", type: :moisture_sensor, moisture: 65.0, battery: 90},
        %{id: "sensor-3", type: :pest_detector, pest_detected: false, battery: 85}
      ]

      Enum.each(telemetry_list, fn telemetry ->
        telemetry = Map.put(telemetry, :timestamp, DateTime.utc_now())
        EventStream.broadcast("telemetry:all", telemetry)
        Process.sleep(10)
      end)

      # Give it time to process all events
      Process.sleep(50)

      # Verify all telemetry was stored
      final_state = TelemetryStorage.get_state()
      assert final_state.telemetry_stored == initial_count + 3
    end

    test "tracks the most recent telemetry in state" do
      # Store first telemetry
      telemetry1 = %{
        id: "sensor-first",
        type: :temperature_sensor,
        temperature: 20.0,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry1)
      Process.sleep(50)

      # Store second telemetry
      telemetry2 = %{
        id: "sensor-second",
        type: :moisture_sensor,
        moisture: 70.0,
        timestamp: DateTime.utc_now(),
        battery: 85
      }

      EventStream.broadcast("telemetry:all", telemetry2)
      Process.sleep(50)

      # Verify the last stored is from the second sensor
      state = TelemetryStorage.get_state()
      assert state.last_stored.id == "sensor-second"
      assert state.last_stored.moisture == 70.0
    end

    test "handles telemetry from different device types" do
      initial_state = TelemetryStorage.get_state()
      initial_count = initial_state.telemetry_stored

      # Send telemetry from various device types
      device_types = [
        %{id: "temp-1", type: :temperature_sensor, temperature: 22.5, battery: 100},
        %{id: "moisture-1", type: :moisture_sensor, moisture: 65.0, battery: 90},
        %{id: "pest-1", type: :pest_detector, pest_detected: true, battery: 85},
        %{id: "gps-1", type: :gps_tracker, location: %{lat: 35.0, lon: -120.0}, battery: 80}
      ]

      Enum.each(device_types, fn telemetry ->
        telemetry = Map.put(telemetry, :timestamp, DateTime.utc_now())
        EventStream.broadcast("telemetry:all", telemetry)
        Process.sleep(10)
      end)

      # Give it time to process all events
      Process.sleep(50)

      # All should be stored
      final_state = TelemetryStorage.get_state()
      assert final_state.telemetry_stored == initial_count + 4
    end

    test "handles telemetry with extra fields" do
      initial_state = TelemetryStorage.get_state()
      initial_count = initial_state.telemetry_stored

      # Telemetry with extra fields
      telemetry = %{
        id: "sensor-extra",
        type: :temperature_sensor,
        temperature: 25.0,
        timestamp: DateTime.utc_now(),
        battery: 100,
        extra_field: "extra_value",
        metadata: %{location: "greenhouse"}
      }

      EventStream.broadcast("telemetry:all", telemetry)
      Process.sleep(50)

      # Should store normally
      new_state = TelemetryStorage.get_state()
      assert new_state.telemetry_stored == initial_count + 1
      assert new_state.last_stored.extra_field == "extra_value"
    end

    test "state persists across multiple telemetry events" do
      # Get initial count
      initial_state = TelemetryStorage.get_state()
      initial_count = initial_state.telemetry_stored

      # Send telemetry
      EventStream.broadcast("telemetry:all", %{
        id: "test-1",
        type: :temperature_sensor,
        temperature: 20.0,
        timestamp: DateTime.utc_now(),
        battery: 100
      })

      Process.sleep(50)

      # Verify count increased
      state1 = TelemetryStorage.get_state()
      assert state1.telemetry_stored == initial_count + 1

      # Send another telemetry
      EventStream.broadcast("telemetry:all", %{
        id: "test-2",
        type: :temperature_sensor,
        temperature: 21.0,
        timestamp: DateTime.utc_now(),
        battery: 95
      })

      Process.sleep(50)

      # Verify count increased again
      state2 = TelemetryStorage.get_state()
      assert state2.telemetry_stored == initial_count + 2
    end
  end

  describe "Integration" do
    test "runs in parallel with LocalRules without conflicts" do
      # Both should be able to process the same telemetry
      telemetry = %{
        id: "parallel-sensor",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      storage_initial = TelemetryStorage.get_state()
      storage_count = storage_initial.telemetry_stored

      EventStream.broadcast("telemetry:all", telemetry)

      # Wait for processing
      Process.sleep(100)

      # TelemetryStorage should have stored it
      storage_final = TelemetryStorage.get_state()
      assert storage_final.telemetry_stored == storage_count + 1

      # Module should still be operational
      assert Process.whereis(TelemetryStorage) != nil
    end
  end
end
