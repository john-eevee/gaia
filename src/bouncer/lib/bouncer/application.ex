defmodule Gaia.Bouncer.Application do
  @moduledoc """
  The Bouncer Application.

  A high-availability OCSP-like server that validates certificate status
  for the reverse proxy authentication system.
  """

  use Application

  alias Gaia.Bouncer.Telemetry

  require Logger

  @impl true
  def start(_type, _args) do
    # Attach telemetry handlers
    Telemetry.attach_handlers()

    children = [
      # HTTP server
      {Bandit, plug: Gaia.Bouncer.Router, scheme: :http, port: port()},
      {Postgrex, database_config()}
    ]

    opts = [strategy: :one_for_one, name: Gaia.Bouncer.Supervisor]
    Logger.info(fn -> "Starting Bouncer server: #{port()}" end)

    Supervisor.start_link(children, opts)
  end

  defp port do
    Application.get_env(:bouncer, :port, 4000)
  end

  defp database_config do
    base = Application.get_env(:bouncer, :database, [])
    Keyword.put_new(base, :name, Bouncer.Database)
  end
end
