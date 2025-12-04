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
  require Logger

  @typedoc """
  A GeoJSON string representing geographic data,
  the string should conform to the GeoJSON specification.
  See: https://tools.ietf.org/html/rfc7946
  """
  @type geo_json() :: String.t()
  @typedoc """
  A UUID string representing a unique identifier.
  """
  @type uuid() :: String.t()
  @typedoc """
    Attributes acknowledged to register a new farm member.
  """
  @type register_farm_attrs() :: %{
          required(:name) => String.t(),
          required(:business_id) => uuid(),
          required(:joined_at) => DateTime.t(),
          required(:location) => geo_json(),
          optional(:boundaries) => geo_json()
        }

  @doc """
  Registers a new farm in the cooperative.
  """
  @spec register_farm(register_farm_attrs()) ::
          {:ok, FarmMember.t()} | {:error, Ecto.Changeset.t()}
  def register_farm(attrs) do
    %FarmMember{}
    |> FarmMember.changeset(attrs)
    |> Repo.insert()
    |> tap(fn
      {:ok, farm_member} ->
        Logger.info("Registered new farm member with ID #{farm_member.id}")

      {:error, changeset} ->
        Logger.error("Failed to register farm member: #{inspect(changeset)}")
    end)
  end
end
