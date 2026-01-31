defmodule Gaia.Hub.CoopIdentity.Farm do
  @moduledoc """
  Schema representing a farm in the cooperative identity system.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Gaia.Hub.CoopIdentity.DataSharingPolicy

  @type t() :: %__MODULE__{
          id: Ecto.UUID.t(),
          name: String.t(),
          business_id: String.t(),
          joined_at: DateTime.t(),
          location: Geo.PostGIS.Geometry.t(),
          boundaries: Geo.PostGIS.Geometry.t() | nil,
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "farms" do
    field(:name, :string)
    field(:business_id, :string)
    field(:joined_at, :utc_datetime_usec)
    field(:location, Geo.PostGIS.Geometry)
    field(:boundaries, Geo.PostGIS.Geometry)

    has_one(:data_sharing_policy, DataSharingPolicy)

    timestamps()
  end

  @doc false
  def changeset(farm, attrs) do
    farm
    |> cast(attrs, [:name, :business_id, :joined_at, :location, :boundaries])
    |> validate_required([:name, :business_id, :joined_at, :location])
  end
end
