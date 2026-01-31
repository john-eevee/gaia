defmodule Gaia.Bouncer.PostgrexDatabase do
  @moduledoc false

  @behaviour Gaia.Bouncer.Database

  # wraps Postgrex queries into a module implementing the Database behaviour
  # to facilitate testing/mocking
  @impl true
  def query(sql, params) do
    Postgrex.query(Bouncer.Database, sql, params)
  end
end
