defmodule Gaia.Bouncer.Application do
  @moduledoc """
  The Bouncer Application.

  A high-availability OCSP-like server that validates certificate status
  for the reverse proxy authentication system.
  """

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    # Attach telemetry handlers
    Gaia.Bouncer.Telemetry.attach_handlers()

    children = [
      # Database connection pool
      {Gaia.Bouncer.Database, []},
      # HTTP server
      {Plug.Cowboy, scheme: :http, plug: Gaia.Bouncer.Router, options: cowboy_options()}
    ]

    opts = [strategy: :one_for_one, name: Gaia.Bouncer.Supervisor]
    Logger.info("Starting Bouncer server on port #{port()}")
    Supervisor.start_link(children, opts)
  end

  defp cowboy_options do
    [
      port: port(),
      transport_options: [num_acceptors: 10]
    ]
  end

  defp port do
    Application.get_env(:bouncer, :port, 4000)
  end
end
