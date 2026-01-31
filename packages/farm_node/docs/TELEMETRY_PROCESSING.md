# Telemetry Processing Architecture

## Overview

Per **ADR-006**, the Farm Node processes telemetry using three parallel modules that all subscribe to the same telemetry source. This architecture ensures clear separation of concerns, resilience, and privacy-by-design.

## The Three Parallel Processors

### 1. TelemetryStorage

**Responsibility**: Store all telemetry locally for future use.

**Module**: `Gaia.FarmNode.TelemetryStorage`

**Subscribes to**: `telemetry:all`

**Actions**:
- Receives all incoming telemetry from devices/broker
- Persists telemetry to Local DB (future: Ecto, current: in-memory tracking)
- Tracks storage metrics (count, last stored)

**Key Principle**: Operates independently of data sharing decisions. ALL telemetry is stored locally, regardless of whether it's shared upstream.

### 2. TelemetrySharing

**Responsibility**: Act as the main gateway for shared data.

**Module**: `Gaia.FarmNode.TelemetrySharing`

**Subscribes to**: `telemetry:all`, `local_alerts`

**Actions**:
- Receives telemetry and alerts
- Checks `DataSharingPolicy` for each item
- Forwards approved data to `HubConnection` for upstream transmission
- Blocks/drops data that policy denies
- Tracks sharing metrics (shared count, blocked count)

**Key Principle**: Privacy-by-design. Default policy is `share_nothing`. TelemetrySharing is the explicit gate where sharing decisions are made.

**Why the name?**: "TelemetrySharing" clearly indicates its role as the gateway for shared data. The previous name "LocalRules" didn't reflect this responsibility and conflated rule evaluation with data sharing decisions.

### 3. LocalRules

**Responsibility**: Evaluate rules and generate alerts.

**Module**: `Gaia.FarmNode.LocalRules`

**Subscribes to**: `telemetry:all`

**Actions**:
- Receives telemetry
- Evaluates configured rules (e.g., "pest detected", "soil dry")
- Broadcasts local alerts via EventStream when rules match
- Tracks alert metrics

**Key Principle**: Focuses solely on rule evaluation. Does NOT check DataSharingPolicy - that's TelemetrySharing's job.

## Architecture Diagram

```
Devices
  |
  v
MQTT Broker
  |
  v
EventStream (telemetry:all)
  |
  +---> TelemetryStorage -----> Local DB
  |
  +---> TelemetrySharing -----> (check policy) ---> HubConnection OR Blocked
  |                                                         |
  |                                                         v
  +---> LocalRules --------> local_alerts                Co-op Hub
                                  |
                                  v
                            TelemetrySharing (check policy for alerts)
```

## Why Parallel Processing?

**Resilience**: If one processor fails, the others continue operating.

**Performance**: No sequential dependencies means faster processing.

**Separation of Concerns**: Each module has a single, clear responsibility.

**Flexibility**: Easy to add new processors without modifying existing ones.

## Default Behavior

- **Storage**: ALL telemetry is stored locally (no filtering)
- **Sharing**: NOTHING is shared (default policy: `share_nothing`)
- **Rules**: Alerts are generated based on configured rules

This ensures the Farm Node remains fully functional offline (Farmer Autonomy) while respecting privacy (Privacy-by-Design).

## Testing

Each processor has its own test suite:
- `telemetry_storage_test.exs`: Verify storage operations
- `telemetry_sharing_test.exs`: Verify policy enforcement and sharing
- `local_rules_test.exs`: Verify rule evaluation

Integration tests verify all three processors work in parallel without conflicts.

## Related

- ADR-006: Device Data Flow
- ADR-001: Core Project Mission (Farmer Autonomy)
- LOCAL_RULES_ENGINE.md: LocalRules implementation details
