# LocalRules Engine (V1)

## Overview

The LocalRules Engine is a real-time telemetry processing system that evaluates rules locally without requiring Hub connectivity. It implements the principle of **Farmer Autonomy** from ADR-001, ensuring that local operations can continue independently of the Hub.

## Architecture

The LocalRules Engine is implemented as a GenServer that:

1. **Subscribes to EventStream**: Receives all telemetry events broadcasted by devices via the `telemetry:all` topic
2. **Evaluates Rules**: Processes incoming telemetry against hardcoded rules
3. **Triggers Alerts**: Broadcasts local alerts when rules are matched via the `local_alerts` topic

### Components

```
┌─────────────────────┐
│   Device Sensors    │
│  (PestDetector,     │
│   TempSensor, etc)  │
└──────────┬──────────┘
           │
           │ broadcasts telemetry
           ▼
┌─────────────────────┐
│  EventStream    │
│   (Pub/Sub via      │
│    Registry)        │
└──────────┬──────────┘
           │
           │ telemetry:all
           ▼
┌─────────────────────┐
│  LocalRules Engine  │
│  - Evaluates rules  │
│  - Triggers alerts  │
└──────────┬──────────┘
           │
           │ broadcasts alerts
           ▼
┌─────────────────────┐
│    local_alerts     │
│      (Topic)        │
└─────────────────────┘
```

## Current Rules (V1)

### Rule 1: Pest Detection Alert

**Trigger Condition**: Telemetry from a `pest_detector` device with `pest_detected: true`

**Action**: Broadcasts a local alert with:
- `type`: `:pest_detected`
- `message`: "Pest detected by device {device_id}"
- `telemetry`: The original telemetry data
- `timestamp`: When the alert was triggered

## Usage

### Subscribing to Alerts

```elixir
# Subscribe to local alerts in your process
{:ok, _} = Gaia.FarmNode.LocalRules.subscribe_alerts()

# Receive alerts
receive do
  {:telemetry, "local_alerts", alert} ->
    IO.inspect(alert, label: "Alert received")
end
```

### Example Alert

```elixir
%{
  type: :pest_detected,
  message: "Pest detected by device pest-sensor-1",
  telemetry: %{
    id: "pest-sensor-1",
    type: :pest_detector,
    pest_detected: true,
    timestamp: ~U[2025-12-23 14:00:00Z],
    battery: 85
  },
  timestamp: ~U[2025-12-23 14:00:00.123Z]
}
```

## Implementation Details

### Supervision Tree

The LocalRules Engine is started as part of the FarmNode application supervision tree:

```elixir
children = [
  {Registry, keys: :unique, name: Gaia.FarmNode.Device.Registry},
  Gaia.FarmNode.EventStream,
  Gaia.FarmNode.Device.Supervisor,
  Gaia.FarmNode.LocalRules  # ← LocalRules Engine
]
```

### State Management

The engine maintains state for monitoring and debugging:

```elixir
%{
  alerts_triggered: 0,      # Total number of alerts triggered
  last_alert: nil          # Most recent alert (for debugging)
}
```

### Real-time Processing

The engine processes telemetry as it arrives, with minimal latency:

1. Device generates telemetry (e.g., every 5 seconds)
2. EventStream broadcasts to `telemetry:all`
3. LocalRules Engine receives and evaluates immediately
4. If rule matches, alert is broadcast within milliseconds

## Testing

The LocalRules Engine includes comprehensive tests:

```bash
cd src/farm_node
mix test test/farm_node/local_rules_test.exs
```

Test coverage includes:
- Engine initialization and subscription
- Pest detection rule evaluation
- Alert triggering and broadcasting
- Counter incrementation
- Integration with real PestDetector devices
- Negative cases (no false positives)

## Future Enhancements (V2+)

Potential improvements for future iterations:

1. **Dynamic Rule Loading**: Load rules from configuration files
2. **Rule DSL**: Domain-specific language for defining rules
3. **Rule Composition**: Combine multiple conditions with AND/OR logic
4. **State Tracking**: Track device state over time for temporal rules
5. **Alert Deduplication**: Prevent repeated alerts for the same condition
6. **Alert Severity Levels**: Critical, Warning, Info
7. **Action System**: Execute actions beyond just alerting (e.g., trigger actuators)
8. **Rule Metrics**: Track rule performance and match statistics

## Design Decisions

### Why GenServer?

A GenServer provides:
- Sequential processing of telemetry (no race conditions)
- State management for tracking alerts
- Easy supervision and fault tolerance
- Process mailbox for buffering telemetry during high load

### Why Hardcoded Rules?

V1 focuses on proving the concept with a simple, reliable implementation:
- No configuration parsing errors
- Predictable behavior
- Easy to test
- Foundation for dynamic rules in V2

### Why Subscribe to `telemetry:all`?

- Simplifies implementation (single subscription)
- Ensures no telemetry is missed
- Easy to add new rules without changing subscriptions
- Performance is acceptable for V1 scale

## Troubleshooting

### Engine Not Starting

Check that the FarmNode application is running:

```elixir
Application.ensure_all_started(:farm_node)
```

### Not Receiving Alerts

Verify subscription:

```elixir
Gaia.FarmNode.LocalRules.subscribe_alerts()
```

Check engine state:

```elixir
Gaia.FarmNode.LocalRules.get_state()
```

### Debugging

Enable logger to see rule triggers:

```elixir
# Alerts are logged at :warning level
Logger.configure(level: :warning)
```

## References

- ADR-001: Core Project Mission (Farmer Autonomy)
- `lib/farm_node/device.ex`: Device behavior and telemetry generation
- `lib/farm_node/device/telemetry_stream.ex`: Pub/Sub implementation
