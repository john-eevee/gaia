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
      Gaia.FarmNode.Device.TelemetryStream,
      Gaia.FarmNode.Device.Supervisor
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: FarmNode.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
