defmodule Gaia.FarmNode.TelemetrySharingTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.TelemetrySharing
  alias Gaia.FarmNode.EventStream

  setup do
    # Ensure the application is started
    Application.ensure_all_started(:farm_node)

    :ok
  end

  describe "TelemetrySharing" do
    test "starts successfully" do
      # The module should be started by the application
      assert Process.whereis(TelemetrySharing) != nil
    end

    test "subscribes to telemetry:all and local_alerts on init" do
      # Verify the module is running and has a state
      state = TelemetrySharing.get_state()
      assert is_map(state)
      assert state.telemetry_shared >= 0
      assert state.telemetry_blocked >= 0
      assert state.alerts_shared >= 0
      assert state.alerts_blocked >= 0
    end

    test "blocks telemetry by default (share_nothing policy)" do
      initial_state = TelemetrySharing.get_state()
      initial_blocked = initial_state.telemetry_blocked

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

      # Verify telemetry was blocked (default policy: share_nothing)
      new_state = TelemetrySharing.get_state()
      assert new_state.telemetry_blocked > initial_blocked
      assert new_state.last_blocked == {:telemetry, telemetry}
    end

    test "blocks alerts by default (share_nothing policy)" do
      initial_state = TelemetrySharing.get_state()
      initial_blocked = initial_state.alerts_blocked

      # Broadcast an alert
      alert = %{
        type: :pest_detected,
        message: "Pest detected by device test-sensor",
        telemetry: %{id: "test-sensor", type: :pest_detector},
        timestamp: DateTime.utc_now()
      }

      EventStream.broadcast("local_alerts", alert)

      # Give it time to process
      Process.sleep(50)

      # Verify alert was blocked (default policy: share_nothing)
      new_state = TelemetrySharing.get_state()
      assert new_state.alerts_blocked > initial_blocked
      assert new_state.last_blocked == {:alert, alert}
    end

    test "processes multiple telemetry events" do
      initial_state = TelemetrySharing.get_state()
      initial_blocked = initial_state.telemetry_blocked

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

      # Verify all telemetry was processed (blocked due to share_nothing)
      final_state = TelemetrySharing.get_state()
      assert final_state.telemetry_blocked > initial_blocked
    end

    test "tracks last blocked telemetry" do
      # Process first telemetry
      telemetry1 = %{
        id: "sensor-first",
        type: :temperature_sensor,
        temperature: 20.0,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry1)
      Process.sleep(50)

      # Process second telemetry
      telemetry2 = %{
        id: "sensor-second",
        type: :moisture_sensor,
        moisture: 70.0,
        timestamp: DateTime.utc_now(),
        battery: 85
      }

      EventStream.broadcast("telemetry:all", telemetry2)
      Process.sleep(50)

      # Verify the last blocked is from the second sensor
      state = TelemetrySharing.get_state()
      assert state.last_blocked == {:telemetry, telemetry2}
    end

    test "tracks last blocked alert" do
      # Process first alert
      alert1 = %{
        type: :pest_detected,
        message: "Pest detected by device sensor-1",
        telemetry: %{id: "sensor-1", type: :pest_detector},
        timestamp: DateTime.utc_now()
      }

      EventStream.broadcast("local_alerts", alert1)
      Process.sleep(50)

      # Process second alert
      alert2 = %{
        type: :pest_detected,
        message: "Pest detected by device sensor-2",
        telemetry: %{id: "sensor-2", type: :pest_detector},
        timestamp: DateTime.utc_now()
      }

      EventStream.broadcast("local_alerts", alert2)
      Process.sleep(50)

      # Verify the last blocked is the second alert
      state = TelemetrySharing.get_state()
      assert state.last_blocked == {:alert, alert2}
    end

    test "handles telemetry from different device types" do
      initial_state = TelemetrySharing.get_state()
      initial_blocked = initial_state.telemetry_blocked

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

      # All should be processed (blocked due to share_nothing)
      final_state = TelemetrySharing.get_state()
      assert final_state.telemetry_blocked > initial_blocked
    end

    test "state persists across multiple events" do
      # Get initial state
      initial_state = TelemetrySharing.get_state()
      initial_blocked = initial_state.telemetry_blocked

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
      state1 = TelemetrySharing.get_state()
      assert state1.telemetry_blocked > initial_blocked

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
      state2 = TelemetrySharing.get_state()
      assert state2.telemetry_blocked > initial_blocked
    end
  end

  describe "Integration" do
    test "runs in parallel with TelemetryStorage and LocalRules" do
      # All three should be able to process the same telemetry
      telemetry = %{
        id: "parallel-sensor",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      sharing_initial = TelemetrySharing.get_state()
      sharing_blocked = sharing_initial.telemetry_blocked

      EventStream.broadcast("telemetry:all", telemetry)

      # Wait for processing
      Process.sleep(100)

      # TelemetrySharing should have processed it (blocked due to share_nothing)
      sharing_final = TelemetrySharing.get_state()
      assert sharing_final.telemetry_blocked > sharing_blocked

      # Module should still be operational
      assert Process.whereis(TelemetrySharing) != nil
    end

    test "processes alerts from LocalRules" do
      # Subscribe to local alerts to verify they're being generated
      {:ok, _} = EventStream.subscribe("local_alerts")

      sharing_initial = TelemetrySharing.get_state()
      alerts_blocked = sharing_initial.alerts_blocked

      # Trigger a pest detection which LocalRules will turn into an alert
      telemetry = %{
        id: "pest-sensor-integration",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry)

      # Wait for LocalRules to process and generate alert
      assert_receive {:event, "local_alerts", _alert}, 1000

      # Give TelemetrySharing time to process the alert
      Process.sleep(100)

      # TelemetrySharing should have processed the alert
      sharing_final = TelemetrySharing.get_state()
      assert sharing_final.alerts_blocked == alerts_blocked + 1
    end
  end

  describe "DataSharingPolicy enforcement" do
    test "acts as the main gateway for shared data" do
      # This test documents that TelemetrySharing is the main gateway
      # where data sharing decisions are made
      state = TelemetrySharing.get_state()

      # State should track both shared and blocked items
      assert Map.has_key?(state, :telemetry_shared)
      assert Map.has_key?(state, :telemetry_blocked)
      assert Map.has_key?(state, :alerts_shared)
      assert Map.has_key?(state, :alerts_blocked)
      assert Map.has_key?(state, :last_shared)
      assert Map.has_key?(state, :last_blocked)
    end

    test "default policy is share_nothing" do
      # Verify that without explicit policy changes, everything is blocked
      initial_state = TelemetrySharing.get_state()
      initial_shared = initial_state.telemetry_shared
      initial_blocked = initial_state.telemetry_blocked

      # Send telemetry
      EventStream.broadcast("telemetry:all", %{
        id: "test-sensor",
        type: :temperature_sensor,
        temperature: 20.0,
        timestamp: DateTime.utc_now(),
        battery: 100
      })

      Process.sleep(50)

      final_state = TelemetrySharing.get_state()
      # Should be blocked, not shared
      assert final_state.telemetry_shared == initial_shared
      assert final_state.telemetry_blocked > initial_blocked
    end
  end
end
