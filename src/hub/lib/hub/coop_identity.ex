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
  alias Gaia.Hub.CoopIdentity.InitialProvisioningKey
  alias Gaia.Hub.Repo
  alias Gaia.Hub.Provision
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

  @typedoc """
  Attributes acknowledged to register a new farmer.
  """
  @type register_farmer_attrs() :: %{
          required(:email) => String.t(),
          required(:first_name) => String.t(),
          required(:last_name) => String.t(),
          required(:role) => Farmer.roles(),
          required(:farm_member_id) => uuid(),
          optional(:password_hash) => String.t(),
          optional(:must_change_password) => boolean()
        }

  @typedoc """
  Attributes for adding a new farm member (admin operation).
  """
  @type add_farm_member_attrs() :: %{
          required(:farm_name) => String.t(),
          required(:business_id) => String.t(),
          required(:location) => geo_json(),
          optional(:boundaries) => geo_json(),
          required(:farmer_email) => String.t(),
          required(:farmer_first_name) => String.t(),
          required(:farmer_last_name) => String.t(),
          required(:farmer_role) => Farmer.roles()
        }

  @typedoc """
  Result of adding a new farm member with provisioning credentials.
  """
  @type add_farm_member_result() :: %{
          farm_member: FarmMember.t(),
          farmer: Farmer.t(),
          provisioning_key: String.t(),
          disposable_password: String.t()
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

  @doc """
  Adds a new farm member to the cooperative (admin operation).

  This is a comprehensive operation that performs the following:
  1. Registers a new farm member in the cooperative
  2. Creates a data sharing policy (all sharing disabled by default)
  3. Generates a secure, single-use provisioning key for the farm node
  4. Creates a farmer account with a disposable password
  5. Marks the farmer to change their password on first login

  ## Parameters

    * `attrs` - A map containing farm and farmer details

  ## Returns

    * `{:ok, result}` - A map containing:
      - `:farm_member` - The created FarmMember
      - `:farmer` - The created Farmer
      - `:provisioning_key` - The plaintext provisioning key (only shown once)
      - `:disposable_password` - The plaintext disposable password (only shown once)
    * `{:error, changeset}` - Validation errors

  ## Examples

      iex> add_new_farm_member(%{
      ...>   farm_name: "Green Valley Farm",
      ...>   business_id: "GVF123",
      ...>   location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
      ...>   farmer_email: "john@greenvalley.com",
      ...>   farmer_first_name: "John",
      ...>   farmer_last_name: "Smith",
      ...>   farmer_role: :owner
      ...> })
      {:ok, %{
        farm_member: %FarmMember{},
        farmer: %Farmer{},
        provisioning_key: "Tractor5-Harvest3-...",
        disposable_password: "Seed8-Plant2-..."
      }}

  ## Important

  The provisioning key and disposable password are only returned once and must be
  securely communicated to the farm member. The keys are stored as hashes and
  cannot be recovered.
  """
  @spec add_new_farm_member(add_farm_member_attrs()) ::
          {:ok, add_farm_member_result()} | {:error, Ecto.Changeset.t()}
  def add_new_farm_member(attrs) do
    # Generate provisioning key and disposable password
    provisioning_key = Provision.generate_intial_provisioning_key()
    disposable_password = Provision.generate_intial_provisioning_key()

    # Hash the keys for storage
    provisioning_key_hash = Provision.hash_provisioning_key(provisioning_key)
    password_hash = Provision.hash_provisioning_key(disposable_password)

    # Set key expiration (30 days from now)
    expires_at = DateTime.add(DateTime.utc_now(), 30, :day)

    farm_attrs = %{
      name: attrs.farm_name,
      business_id: attrs.business_id,
      joined_at: DateTime.utc_now(),
      location: attrs.location,
      boundaries: Map.get(attrs, :boundaries)
    }

    Ecto.Multi.new()
    |> Ecto.Multi.insert(:farm_member, FarmMember.changeset(%FarmMember{}, farm_attrs))
    |> Ecto.Multi.insert(:data_sharing_policy, fn %{farm_member: farm_member} ->
      DataSharingPolicy.changeset(%DataSharingPolicy{}, %{farm_member_id: farm_member.id})
    end)
    |> Ecto.Multi.insert(:provisioning_key, fn %{farm_member: farm_member} ->
      InitialProvisioningKey.changeset(%InitialProvisioningKey{}, %{
        key_hash: provisioning_key_hash,
        expires_at: expires_at,
        farm_member_id: farm_member.id
      })
    end)
    |> Ecto.Multi.insert(:farmer, fn %{farm_member: farm_member} ->
      Farmer.changeset(%Farmer{}, %{
        email: attrs.farmer_email,
        first_name: attrs.farmer_first_name,
        last_name: attrs.farmer_last_name,
        role: attrs.farmer_role,
        farm_member_id: farm_member.id,
        password_hash: password_hash,
        must_change_password: true
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{farm_member: farm_member, farmer: farmer}} ->
        Logger.info(
          "Added new farm member #{farm_member.id} with farmer #{farmer.id}. " <>
            "Provisioning key and disposable password generated."
        )

        {:ok,
         %{
           farm_member: farm_member,
           farmer: farmer,
           provisioning_key: provisioning_key,
           disposable_password: disposable_password
         }}

      {:error, _failed_operation, changeset, _changes_so_far} ->
        Logger.error("Failed to add new farm member: #{inspect(changeset)}")
        {:error, changeset}
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
