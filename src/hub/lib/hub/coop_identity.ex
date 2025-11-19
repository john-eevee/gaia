defmodule Gaia.Hub.CoopIdentity do
  @moduledoc """
  The CoopIdentity context.

  The principal application service responsivble for delegating and managing
  low level operations into a use cases exposed to clients. This includes
  managing farm member identities, their credentials, and associated metadata.

  All use case calls returns a tuple of either `{:ok, result}`
   or `{:error, reason}`.

  A use case can dispatch domain events to signal important state changes
  within the cooperative identity system. Enabling
  """

  alias Gaia.Hub.CoopIdentity.FarmMember
  alias Gaia.Hub.Repo

  @doc """
  Registers a new farm in the cooperative.
  """
  def register_farm(attrs) do
    %FarmMember{}
    |> FarmMember.changeset(attrs)
    |> Repo.insert()
  end
end
