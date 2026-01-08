defmodule Gaia.FarmNode.EventStream do
  @moduledoc """
  Simple pub/sub for event broadcasting within the FarmNode.

  Usage:
      {:ok, _} = Gaia.FarmNode.EventStream.subscribe("pest_events")
    Gaia.FarmNode.EventStream.broadcast("pest_events", %{pest_detected: true})
    # Subscribers will receive messages using an envelope inferred from the topic prefix:
    # - topics starting with "telemetry:" are delivered as {:telemetry, topic, payload}
    # - topics starting with "event:" are delivered as {:event, topic, payload}
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

  @doc "Broadcast a payload to all subscribers of a topic. Envelope is chosen by topic prefix."
  def broadcast(topic, payload) when is_binary(topic) or is_atom(topic) do
    Registry.dispatch(@registry, topic, fn entries ->
      envelope = topic |> to_string() |> envelope_for()

      for {pid, _} <- entries do
        send(pid, {envelope, topic, payload})
      end
    end)
  end

  defp envelope_for("telemetry:" <> _rest), do: :telemetry
  defp envelope_for("event:" <> _rest), do: :event
  defp envelope_for(_), do: :event
end
