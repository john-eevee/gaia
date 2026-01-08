defmodule Gaia.FarmNode.LocalRules do
  @moduledoc """
  LocalRules Engine (V1) - Processes telemetry and evaluates rules locally without Hub connectivity.

  This module implements a basic rule evaluator that acts on telemetry data in real-time.
  It subscribes to the EventStream and evaluates hardcoded rules against incoming telemetry.
  """

  use GenServer
  require Logger

  alias Gaia.FarmNode.EventStream

  @type alert :: %{
          type: atom(),
          message: String.t(),
          telemetry: map(),
          timestamp: DateTime.t()
        }

  ## Client API

  @doc """
  Starts the LocalRules engine.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Subscribe to local alerts triggered by the rules engine.
  """
  def subscribe_alerts do
    EventStream.subscribe("local_alerts")
  end

  @doc """
  Get the current state of the rules engine (for debugging/testing).
  """
  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Subscribe to device telemetry (incoming device data)
    {:ok, _} = EventStream.subscribe("telemetry:all")
    Logger.info("LocalRules engine started and subscribed to telemetry:all")

    state = %{
      alerts_triggered: 0,
      last_alert: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:telemetry, _topic, telemetry}, state) do
    # Evaluate all rules against the incoming telemetry
    new_state = evaluate_rules(telemetry, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  ## Private Functions

  # Evaluate all hardcoded rules against telemetry
  defp evaluate_rules(telemetry, state) do
    # Rule 1: IF EventStream contains pest-type-A THEN trigger LocalAlert
    state = evaluate_pest_detection_rule(telemetry, state)

    state
  end

  # Hardcoded Rule: Pest Detection Alert
  # Triggers when pest_detected is true in telemetry from pest_detector devices
  defp evaluate_pest_detection_rule(telemetry, state) do
    case telemetry do
      %{type: :pest_detector, pest_detected: true, id: device_id} ->
        alert = %{
          type: :pest_detected,
          message: "Pest detected by device #{device_id}",
          telemetry: telemetry,
          timestamp: DateTime.utc_now()
        }

        # Broadcast the alert
        EventStream.broadcast("local_alerts", alert)

        Logger.warning("LocalRule triggered: #{alert.message}")

        # Update state
        %{
          state
          | alerts_triggered: state.alerts_triggered + 1,
            last_alert: alert
        }

      _ ->
        # Rule not matched
        state
    end
  end
end
