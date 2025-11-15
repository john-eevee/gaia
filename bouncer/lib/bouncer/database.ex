defmodule Gaia.Bouncer.Database do
  @moduledoc """
  Database behaviour module for Bouncer.
  """

  @callback query(String.t(), list()) :: {:ok, any()} | {:error, any()}

end
