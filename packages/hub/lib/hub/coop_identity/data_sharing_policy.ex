defmodule Gaia.Hub.CoopIdentity.DataSharingPolicy do
  @moduledoc """
  Schema representing a farm's data sharing policy.

  This schema tracks which types of data a farm has agreed to share
  with the cooperative. All fields default to `false`, meaning no data is
  shared unless explicitly enabled by the farm.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Gaia.Hub.CoopIdentity.Farm

  @type t() :: %__MODULE__{
          id: Ecto.UUID.t(),
          share_anonymous_soil_data: boolean(),
          share_pest_sightings: boolean(),
          share_yield_data: boolean(),
          farm_id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "data_sharing_policies" do
    field(:share_anonymous_soil_data, :boolean, default: false)
    field(:share_pest_sightings, :boolean, default: false)
    field(:share_yield_data, :boolean, default: false)

    belongs_to(:farm, Farm)

    timestamps()
  end

  @doc false
  def changeset(data_sharing_policy, attrs) do
    data_sharing_policy
    |> cast(attrs, [
      :share_anonymous_soil_data,
      :share_pest_sightings,
      :share_yield_data,
      :farm_id
    ])
    |> validate_required([:farm_id])
    |> foreign_key_constraint(:farm_id)
    |> unique_constraint(:farm_id)
  end
end
