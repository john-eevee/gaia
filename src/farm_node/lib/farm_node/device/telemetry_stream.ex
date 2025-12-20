defmodule Gaia.FarmNode.Device.TelemetryStream do
  @moduledoc """
  Simple pub/sub for device telemetry using Registry.

  Usage:
    {:ok, _} = Gaia.FarmNode.Device.TelemetryStream.subscribe("pest_events")
    Gaia.FarmNode.Device.TelemetryStream.broadcast("pest_events", %{pest_detected: true})
  """

  @registry __MODULE__

  def child_spec(_) do
    %{
      id: @registry,
      start: {Registry, :start_link, [[keys: :duplicate, name: @registry]]}
    }
  end

  @doc "Subscribe the current process to a topic"
  def subscribe(topic) when is_binary(topic) or is_atom(topic) do
    Registry.register(@registry, topic, nil)
  end

  @doc "Unsubscribe the current process from a topic"
  def unsubscribe(topic) when is_binary(topic) or is_atom(topic) do
    Registry.unregister(@registry, topic)
  end

  @doc "Broadcast a payload to all subscribers of a topic"
  def broadcast(topic, payload) when is_binary(topic) or is_atom(topic) do
    Registry.dispatch(@registry, topic, fn entries ->
      for {pid, _} <- entries do
        send(pid, {:telemetry, topic, payload})
      end
    end)
  end
end
