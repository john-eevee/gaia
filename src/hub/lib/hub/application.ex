defmodule Gaia.Hub.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  alias Gaia.Hub.Provision.Diceware

  def start(_type, _args) do
    # Start the Diceware dictionary
    Diceware.init()

    children = [
      Gaia.Hub.Repo
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Gaia.Hub.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
