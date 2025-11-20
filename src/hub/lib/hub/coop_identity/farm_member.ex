defmodule Gaia.Hub.CoopIdentity.FarmMember do
  @moduledoc """
  Schema representing a farm member in the cooperative identity system.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "farm_members" do
    field(:name, :string)
    field(:business_id, :string)
    field(:joined_at, :utc_datetime_usec)
    field(:location, Geo.PostGIS.Geometry)
    field(:boundaries, Geo.PostGIS.Geometry)

    timestamps()
  end

  @doc false
  def changeset(farm_member, attrs) do
    farm_member
    |> cast(attrs, [:name, :business_id, :joined_at, :location, :boundaries])
    |> validate_required([:name, :business_id, :joined_at, :location])
  end
end
