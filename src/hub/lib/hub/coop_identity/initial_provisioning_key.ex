defmodule Gaia.Hub.CoopIdentity.InitialProvisioningKey do
  @moduledoc """
  Schema representing a secure, single-use provisioning key for onboarding new farm members.

  The provisioning key is generated when an admin creates a new FarmMember and is used
  during the initial provisioning process. Once used, the key is invalidated to prevent reuse.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Gaia.Hub.CoopIdentity.FarmMember

  @type t() :: %__MODULE__{
          id: Ecto.UUID.t(),
          key_hash: String.t(),
          used: boolean(),
          expires_at: DateTime.t(),
          farm_member_id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "initial_provisioning_keys" do
    field(:key_hash, :string)
    field(:used, :boolean, default: false)
    field(:expires_at, :utc_datetime_usec)

    belongs_to(:farm_member, FarmMember)

    timestamps()
  end

  @doc false
  def changeset(initial_provisioning_key, attrs) do
    initial_provisioning_key
    |> cast(attrs, [:key_hash, :used, :expires_at, :farm_member_id])
    |> validate_required([:key_hash, :expires_at, :farm_member_id])
    |> unique_constraint(:farm_member_id)
    |> foreign_key_constraint(:farm_member_id)
  end

  @doc """
  Marks the provisioning key as used.
  """
  def mark_as_used(initial_provisioning_key) do
    changeset(initial_provisioning_key, %{used: true})
  end
end
