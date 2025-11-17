defmodule Gaia.Bouncer.Telemetry do
  @moduledoc """
  Telemetry setup and handlers for the Bouncer server.

  Tracks:
  - Request processing time
  - Failure counter
  """

  require Logger

  @doc """
  Attaches telemetry event handlers.
  """
  def attach_handlers do
    :telemetry.attach_many(
      "bouncer-telemetry",
      [
        [:bouncer, :request, :success],
        [:bouncer, :request, :failure]
      ],
      &handle_event/4,
      nil
    )
  end

  @doc """
  Handles telemetry events and logs metrics.
  """
  def handle_event([:bouncer, :request, :success], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    Logger.info(
      "Request succeeded in #{duration_ms}ms, status: #{metadata.status}",
      duration_ms: duration_ms,
      status: metadata.status
    )
  end

  def handle_event([:bouncer, :request, :failure], measurements, _metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    Logger.warning(
      "Request failed in #{duration_ms}ms",
      duration_ms: duration_ms
    )
  end

  def measure(fun) when is_function(fun, 0) do
    start_time = System.monotonic_time()
    result = fun.()
    duration = System.monotonic_time() - start_time
    {result, duration}
  end
end
