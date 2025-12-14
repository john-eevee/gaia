defmodule Gaia.Hub.CoopIdentity.DataSharingPolicyFixtures do
  @moduledoc false

  @doc """
  Generate valid attributes for a data sharing policy with all fields set to false (default).
  """
  def valid_data_sharing_policy_attrs(farm_member_id) do
    %{
      farm_member_id: farm_member_id,
      share_anonymous_soil_data: false,
      share_pest_sightings: false,
      share_yield_data: false
    }
  end

  @doc """
  Generate attributes for a data sharing policy with all sharing enabled.
  """
  def all_sharing_enabled_attrs(farm_member_id) do
    %{
      farm_member_id: farm_member_id,
      share_anonymous_soil_data: true,
      share_pest_sightings: true,
      share_yield_data: true
    }
  end
end
