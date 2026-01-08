defmodule Gaia.FarmNode.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Registry for devices
      {Registry, keys: :unique, name: Gaia.FarmNode.Device.Registry},
      Gaia.FarmNode.EventStream,
      Gaia.FarmNode.Device.Supervisor,
      # Parallel telemetry processors (per ADR-006)
      Gaia.FarmNode.TelemetryStorage,
      Gaia.FarmNode.TelemetrySharing,
      Gaia.FarmNode.LocalRules
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: FarmNode.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
