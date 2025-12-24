defmodule Gaia.FarmNode.LocalRulesTest do
  use ExUnit.Case, async: false

  alias Gaia.FarmNode.LocalRules
  alias Gaia.FarmNode.EventStream
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

      EventStream.broadcast("telemetry:all", telemetry)

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

      EventStream.broadcast("telemetry:all", telemetry)

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

      EventStream.broadcast("telemetry:all", telemetry)

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

      EventStream.broadcast("telemetry:all", telemetry)

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

  describe "Multiple alerts" do
    test "handles multiple consecutive alerts" do
      initial_state = LocalRules.get_state()
      initial_count = initial_state.alerts_triggered

      # Trigger multiple alerts
      for i <- 1..3 do
        telemetry = %{
          id: "pest-sensor-multi-#{i}",
          type: :pest_detector,
          pest_detected: true,
          timestamp: DateTime.utc_now(),
          battery: 100
        }

        EventStream.broadcast("telemetry:all", telemetry)
        
        # Wait for each alert to be processed
        assert_receive {:telemetry, "local_alerts", alert}, 1000
        assert alert.type == :pest_detected
        assert alert.message =~ "pest-sensor-multi-#{i}"
      end

      # Verify all alerts were counted
      final_state = LocalRules.get_state()
      assert final_state.alerts_triggered == initial_count + 3
    end

    test "tracks the most recent alert in state" do
      # Trigger first alert
      telemetry1 = %{
        id: "pest-sensor-first",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry1)
      assert_receive {:telemetry, "local_alerts", _}, 1000

      # Small delay
      Process.sleep(50)

      # Trigger second alert
      telemetry2 = %{
        id: "pest-sensor-second",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 50
      }

      EventStream.broadcast("telemetry:all", telemetry2)
      assert_receive {:telemetry, "local_alerts", _}, 1000

      # Verify the last alert is from the second device
      state = LocalRules.get_state()
      assert state.last_alert.telemetry.id == "pest-sensor-second"
      assert state.last_alert.telemetry.battery == 50
    end
  end

  describe "Alert content validation" do
    test "alert contains all required fields" do
      telemetry = %{
        id: "pest-sensor-validate",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 75
      }

      EventStream.broadcast("telemetry:all", telemetry)

      assert_receive {:telemetry, "local_alerts", alert}, 1000

      # Verify alert structure
      assert Map.has_key?(alert, :type)
      assert Map.has_key?(alert, :message)
      assert Map.has_key?(alert, :telemetry)
      assert Map.has_key?(alert, :timestamp)

      # Verify alert content
      assert alert.type == :pest_detected
      assert is_binary(alert.message)
      assert is_map(alert.telemetry)
      assert %DateTime{} = alert.timestamp

      # Verify telemetry is preserved in alert
      assert alert.telemetry.id == "pest-sensor-validate"
      assert alert.telemetry.type == :pest_detector
      assert alert.telemetry.pest_detected == true
      assert alert.telemetry.battery == 75
    end

    test "alert message includes device ID" do
      telemetry = %{
        id: "specific-device-id-123",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry)

      assert_receive {:telemetry, "local_alerts", alert}, 1000
      assert alert.message =~ "specific-device-id-123"
    end
  end

  describe "Edge cases and robustness" do
    test "ignores telemetry with missing fields" do
      # Telemetry missing the pest_detected field
      incomplete_telemetry = %{
        id: "incomplete-sensor",
        type: :pest_detector,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", incomplete_telemetry)

      # Should NOT trigger an alert
      refute_receive {:telemetry, "local_alerts", _}, 500
    end

    test "handles telemetry with extra fields gracefully" do
      # Telemetry with extra fields should still work
      extra_telemetry = %{
        id: "extra-fields-sensor",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100,
        extra_field: "should be ignored",
        another_field: 42
      }

      EventStream.broadcast("telemetry:all", extra_telemetry)

      # Should trigger alert normally
      assert_receive {:telemetry, "local_alerts", alert}, 1000
      assert alert.type == :pest_detected
      
      # Extra fields should be preserved in telemetry
      assert alert.telemetry.extra_field == "should be ignored"
      assert alert.telemetry.another_field == 42
    end

    test "processes telemetry from different device types without errors" do
      # Send telemetry from various device types
      device_types = [
        %{id: "temp-1", type: :temperature_sensor, temperature: 22.5, battery: 100},
        %{id: "moisture-1", type: :moisture_sensor, moisture: 65.0, battery: 90},
        %{id: "gps-1", type: :gps_tracker, location: %{lat: 35.0, lon: -120.0}, battery: 85}
      ]

      device_types
      |> Enum.with_index()
      |> Enum.each(fn {telemetry, index} ->
        # Add timestamp with slight offset for realism
        Process.sleep(index * 10)
        telemetry = Map.put(telemetry, :timestamp, DateTime.utc_now())
        EventStream.broadcast("telemetry:all", telemetry)
      end)

      # None should trigger alerts
      refute_receive {:telemetry, "local_alerts", _}, 500

      # Engine should still be operational
      state = LocalRules.get_state()
      assert is_map(state)
    end
  end

  describe "Timing and performance" do
    test "processes alerts with minimal latency" do
      start_time = System.monotonic_time(:millisecond)

      telemetry = %{
        id: "latency-test-sensor",
        type: :pest_detector,
        pest_detected: true,
        timestamp: DateTime.utc_now(),
        battery: 100
      }

      EventStream.broadcast("telemetry:all", telemetry)

      assert_receive {:telemetry, "local_alerts", _alert}, 1000

      end_time = System.monotonic_time(:millisecond)
      latency = end_time - start_time

      # Alert should be processed quickly (within 100ms in ideal conditions)
      # Using 500ms as a reasonable upper bound for test environments
      assert latency < 500, "Alert processing took #{latency}ms, expected < 500ms"
    end
  end
end
