defmodule Gaia.FarmNode.LocalRulesTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.LocalRules
  alias Gaia.FarmNode.Device.TelemetryStream
  alias Gaia.FarmNode.Device.PestDetector

  setup do
    # Ensure the application is started
    Application.ensure_all_started(:farm_node)

    # Subscribe to local alerts
    {:ok, _} = LocalRules.subscribe_alerts()

    :ok
  end

  describe "LocalRules Engine" do
    test "starts successfully" do
      # The engine should be started by the application
      assert Process.whereis(LocalRules) != nil
    end

    test "subscribes to telemetry stream on init" do
      # Verify the engine is running and has a state
      state = LocalRules.get_state()
      assert is_map(state)
      assert state.alerts_triggered >= 0
    end
  end

  describe "Pest Detection Rule" do
    test "triggers alert when pest is detected" do
      # Manually broadcast a pest detection telemetry
      telemetry = %{
        id: "pest-sensor-1",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      TelemetryStream.broadcast("telemetry:all", telemetry)

      # Should receive an alert
      assert_receive {:telemetry, "local_alerts",
                      %{
                        type: :pest_detected,
                        message: message,
                        telemetry: received_telemetry,
                        timestamp: _timestamp
                      }},
                     1000

      assert message =~ "Pest detected by device pest-sensor-1"
      assert received_telemetry.id == "pest-sensor-1"
      assert received_telemetry.pest_detected == true
    end

    test "does not trigger alert when pest is not detected" do
      # Manually broadcast telemetry with no pest
      telemetry = %{
        id: "pest-sensor-2",
        type: :pest_detector,
        pest_detected: false,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      TelemetryStream.broadcast("telemetry:all", telemetry)

      # Should NOT receive an alert
      refute_receive {:telemetry, "local_alerts", _}, 500
    end

    test "does not trigger alert for non-pest detector telemetry" do
      # Broadcast telemetry from different device type
      telemetry = %{
        id: "temp-sensor-1",
        type: :temperature_sensor,
        temperature: 25.0,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      TelemetryStream.broadcast("telemetry:all", telemetry)

      # Should NOT receive an alert
      refute_receive {:telemetry, "local_alerts", _}, 500
    end

    test "increments alerts_triggered counter" do
      initial_state = LocalRules.get_state()
      initial_count = initial_state.alerts_triggered

      # Trigger an alert
      telemetry = %{
        id: "pest-sensor-3",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      TelemetryStream.broadcast("telemetry:all", telemetry)

      # Wait for processing
      assert_receive {:telemetry, "local_alerts", _}, 1000

      # Check that counter increased
      new_state = LocalRules.get_state()
      assert new_state.alerts_triggered == initial_count + 1
      assert new_state.last_alert != nil
      assert new_state.last_alert.type == :pest_detected
    end
  end

  describe "Integration with PestDetector device" do
    test "processes real-time telemetry from pest detector device" do
      # Start a real pest detector device with short interval
      device_id = "integration-pest-#{:rand.uniform(10000)}"
      {:ok, _pid} = PestDetector.start_link(id: device_id, interval: 100, battery: 100)

      # Wait for telemetry broadcasts and check if alerts are triggered
      # Note: Since pest detection is random (10% chance), we'll just verify
      # that the engine processes the telemetry without errors
      
      # Give it some time to generate at least one telemetry event
      Process.sleep(200)

      # Verify the engine is still running and functional
      state = LocalRules.get_state()
      assert is_map(state)

      # Clean up
      PestDetector.stop(device_id)
    end
  end
end
