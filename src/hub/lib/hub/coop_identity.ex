defmodule Gaia.Hub.CoopIdentity do
  @moduledoc """
  The CoopIdentity context.

  The principal application service responsible for delegating and managing
  low level operations into a use cases exposed to clients. This includes
  managing farm member identities, their credentials, and associated metadata.

  All use case calls returns a tuple of either `{:ok, result}`
   or `{:error, reason}`.

  A use case can dispatch domain events to signal important state changes
  within the cooperative identity system. Enabling
  """

  alias Gaia.Hub.CoopIdentity.FarmMember
  alias Gaia.Hub.CoopIdentity.Farmer
  alias Gaia.Hub.CoopIdentity.DataSharingPolicy
  alias Gaia.Hub.Repo
  require Logger
  import Ecto.Query

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

  @typedoc """
  Attributes acknowledged to register a new farmer.
  """
  @type register_farmer_attrs() :: %{
          required(:email) => String.t(),
          required(:first_name) => String.t(),
          required(:last_name) => String.t(),
          required(:role) => Farmer.roles(),
          required(:farm_member_id) => uuid()
        }

  @doc """
  Registers a new farm in the cooperative.

  Creates a FarmMember and its associated DataSharingPolicy with all
  sharing options set to false by default.
  """
  @spec register_farm(register_farm_attrs()) ::
          {:ok, FarmMember.t()} | {:error, Ecto.Changeset.t()}
  def register_farm(attrs) do
    Ecto.Multi.new()
    |> Ecto.Multi.insert(:farm_member, FarmMember.changeset(%FarmMember{}, attrs))
    |> Ecto.Multi.insert(:data_sharing_policy, fn %{farm_member: farm_member} ->
      DataSharingPolicy.changeset(%DataSharingPolicy{}, %{farm_member_id: farm_member.id})
    end)
    |> Repo.transaction()
    |> then(fn
      {:ok, %{farm_member: farm_member}} ->
        Logger.info(
          "Registered new farm member with ID #{farm_member.id} and default data sharing policy (all disabled)"
        )

        {:ok, farm_member}

      {:error, _failed_operation, changeset, _changes_so_far} ->
        Logger.error("Failed to register farm member: #{inspect(changeset)}")
        {:error, changeset}
    end)
  end

  @spec register_farmer(register_farmer_attrs()) ::
          {:ok, Farmer.t()} | {:error, Ecto.Changeset.t()}
  def register_farmer(attrs) do
    %Farmer{}
    |> Farmer.changeset(attrs)
    |> Repo.insert()
    |> tap(fn
      {:ok, farmer} ->
        Logger.info("Registered new farmer with ID #{farmer.id} on farm #{farmer.farm_member_id}")

      {:error, changeset} ->
        Logger.error("Failed to register farmer: #{inspect(changeset)}")
    end)
  end

  @typedoc """
  Attributes for toggling data sharing policy settings.
  """
  @type toggle_policy_attrs() :: %{
          optional(:share_anonymous_soil_data) => boolean(),
          optional(:share_pest_sightings) => boolean(),
          optional(:share_yield_data) => boolean()
        }

  @doc """
  Toggles data sharing policy settings for a farm member.

  This function allows updating one or more data sharing preferences
  for a farm member. All changes are logged for audit purposes.

  ## Parameters

    * `farm_member_id` - The UUID of the farm member
    * `attrs` - A map of policy fields to update

  ## Returns

    * `{:ok, data_sharing_policy}` - Updated policy
    * `{:error, changeset}` - Validation errors
    * `{:error, :not_found}` - Farm member or policy not found

  ## Examples

      iex> toggle_data_sharing_policy(farm_id, %{share_pest_sightings: true})
      {:ok, %DataSharingPolicy{share_pest_sightings: true}}

  """
  @spec toggle_data_sharing_policy(uuid(), toggle_policy_attrs()) ::
          {:ok, DataSharingPolicy.t()} | {:error, Ecto.Changeset.t()} | {:error, :not_found}
  def toggle_data_sharing_policy(farm_member_id, attrs) do
    case Repo.get_by(DataSharingPolicy, farm_member_id: farm_member_id) do
      nil ->
        Logger.warning(
          "Attempted to toggle policy for non-existent farm member #{farm_member_id}"
        )

        {:error, :not_found}

      policy ->
        old_values =
          Map.take(policy, [:share_anonymous_soil_data, :share_pest_sightings, :share_yield_data])

        policy
        |> DataSharingPolicy.changeset(attrs)
        |> Repo.update()
        |> tap(fn
          {:ok, updated_policy} ->
            log_changes(updated_policy, old_values, farm_member_id)

          {:error, changeset} ->
            Logger.error(
              "Failed to update data sharing policy for farm member #{farm_member_id}: #{inspect(changeset)}"
            )
        end)
    end
  end

  defp log_changes(updated_policy, old_values, farm_member_id) do
    new_values =
      Map.take(updated_policy, [
        :share_anonymous_soil_data,
        :share_pest_sightings,
        :share_yield_data
      ])

    changes =
      for {key, new_val} <- new_values,
          Map.get(old_values, key) != new_val,
          do: {key, Map.get(old_values, key), new_val}

    if changes != [] do
      Logger.info(
        "Data sharing policy updated for farm member #{farm_member_id}: " <>
          Enum.map_join(changes, ", ", fn {field, old_val, new_val} ->
            "#{field} changed from #{old_val} to #{new_val}"
          end)
      )
    end
  end
end
