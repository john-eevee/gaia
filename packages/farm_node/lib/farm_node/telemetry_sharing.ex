defmodule Gaia.FarmNode.TelemetrySharing do
  @moduledoc """
  TelemetrySharing - Main gateway for shared data to pass through.

  This module subscribes to telemetry events and checks against the DataSharingPolicy.
  If the policy allows sharing, telemetry/alerts are forwarded to HubConnection for
  upstream transmission. Otherwise, data is kept local-only.

  Per ADR-006, this module runs in parallel with TelemetryStorage and LocalRules,
  all subscribing to the same telemetry source. TelemetrySharing acts as the explicit
  gate for data leaving the farm node, implementing privacy-by-design principles.

  Responsibilities:
  - Subscribe to telemetry events from the broker/devices
  - Check DataSharingPolicy for each telemetry/alert
  - Forward approved data to HubConnection
  - Drop/keep local data that should not be shared

  Default behavior: share_nothing (per project rules)
  """

  use GenServer
  require Logger

  alias Gaia.FarmNode.EventStream

  @type telemetry :: map()
  @type alert :: map()

  ## Client API

  @doc """
  Starts the TelemetrySharing process.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the current state of the sharing module (for debugging/testing).
  """
  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Subscribe to device telemetry and local alerts
    {:ok, _} = EventStream.subscribe("telemetry:all")
    {:ok, _} = EventStream.subscribe("local_alerts")
    Logger.info("TelemetrySharing started and subscribed to telemetry:all and local_alerts")

    state = %{
      telemetry_shared: 0,
      telemetry_blocked: 0,
      alerts_shared: 0,
      alerts_blocked: 0,
      last_shared: nil,
      last_blocked: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:telemetry, _topic, telemetry}, state) do
    # Check policy and potentially share telemetry
    new_state = process_telemetry(telemetry, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:event, "local_alerts", alert}, state) do
    # Check policy and potentially share alert
    new_state = process_alert(alert, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  ## Private Functions

  # Process telemetry and check against DataSharingPolicy
  defp process_telemetry(telemetry, state) do
    if should_share_telemetry?(telemetry) do
      Logger.debug(
        "TelemetrySharing: Sharing telemetry from device #{telemetry[:id]} to HubConnection"
      )

      # TODO: Forward to HubConnection.push_telemetry(telemetry)
      # For now, just track in state

      %{
        state
        | telemetry_shared: state.telemetry_shared + 1,
          last_shared: {:telemetry, telemetry}
      }
    else
      Logger.debug(
        "TelemetrySharing: Blocking telemetry from device #{telemetry[:id]} (policy denies)"
      )

      %{
        state
        | telemetry_blocked: state.telemetry_blocked + 1,
          last_blocked: {:telemetry, telemetry}
      }
    end
  end

  # Process alert and check against DataSharingPolicy
  defp process_alert(alert, state) do
    if should_share_alert?(alert) do
      Logger.debug("TelemetrySharing: Sharing alert type=#{alert[:type]} to HubConnection")

      # TODO: Forward to HubConnection.push_alert(alert)
      # For now, just track in state

      %{
        state
        | alerts_shared: state.alerts_shared + 1,
          last_shared: {:alert, alert}
      }
    else
      Logger.debug("TelemetrySharing: Blocking alert type=#{alert[:type]} (policy denies)")

      %{
        state
        | alerts_blocked: state.alerts_blocked + 1,
          last_blocked: {:alert, alert}
      }
    end
  end

  # Check if telemetry should be shared based on DataSharingPolicy
  # Default: share_nothing (per project rules)
  defp should_share_telemetry?(_telemetry) do
    # TODO: Implement actual DataSharingPolicy check
    # For now, default to share_nothing
    false
  end

  # Check if alert should be shared based on DataSharingPolicy
  # Default: share_nothing (per project rules)
  defp should_share_alert?(_alert) do
    # TODO: Implement actual DataSharingPolicy check
    # For now, default to share_nothing
    false
  end
end
