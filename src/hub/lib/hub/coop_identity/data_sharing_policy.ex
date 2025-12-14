defmodule Gaia.Hub.CoopIdentity.DataSharingPolicy do
  @moduledoc """
  Schema representing a farm member's data sharing policy.

  This schema tracks which types of data a farm member has agreed to share
  with the cooperative. All fields default to `false`, meaning no data is
  shared unless explicitly enabled by the farm member.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Gaia.Hub.CoopIdentity.FarmMember

  @type t() :: %__MODULE__{
          id: Ecto.UUID.t(),
          share_anonymous_soil_data: boolean(),
          share_pest_sightings: boolean(),
          share_yield_data: boolean(),
          farm_member_id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "data_sharing_policies" do
    field(:share_anonymous_soil_data, :boolean, default: false)
    field(:share_pest_sightings, :boolean, default: false)
    field(:share_yield_data, :boolean, default: false)

    belongs_to(:farm_member, FarmMember)

    timestamps()
  end

  @doc false
  def changeset(data_sharing_policy, attrs) do
    data_sharing_policy
    |> cast(attrs, [
      :share_anonymous_soil_data,
      :share_pest_sightings,
      :share_yield_data,
      :farm_member_id
    ])
    |> validate_required([:farm_member_id])
    |> foreign_key_constraint(:farm_member_id)
    |> unique_constraint(:farm_member_id)
  end
end
