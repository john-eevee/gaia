defmodule Gaia.Hub.CoopIdentity.Farmer do
  @moduledoc """
  Represents a human user associated with a `Gaia.Hub.CoopIdentity.FarmMember`.

  While `FarmMember` represents the legal business entity or the physical farm node
  registered in the cooperative, `Farmer` represents the individuals who manage
  and operate that farm.

  ## Roles
  Farmers have specific roles that dictate their permissions within the context of their farm:
  * `:owner` - Full control over the farm's identity, data sharing policies, and staff management.
  * `:staff` - Operational access for day-to-day tasks but cannot modify critical farm settings.
  * `:admin` - Administrative access for managing the farm's integration with the Hub.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Gaia.Hub.CoopIdentity.FarmMember

  @type roles() :: :owner | :staff | :admin

  @type t() :: %__MODULE__{
          id: Ecto.UUID.t(),
          email: String.t(),
          first_name: String.t(),
          last_name: String.t(),
          role: roles(),
          farm_member_id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "farmers" do
    field(:email, :string)
    field(:first_name, :string)
    field(:last_name, :string)
    field(:role, Ecto.Enum, values: [:owner, :staff, :admin])

    belongs_to(:farm_member, FarmMember)

    timestamps()
  end

  @doc false
  def changeset(farmer, attrs) do
    farmer
    |> cast(attrs, [:email, :first_name, :last_name, :role, :farm_member_id])
    |> validate_required([:email, :first_name, :last_name, :role, :farm_member_id])
    |> unique_constraint(:email)
  end
end
