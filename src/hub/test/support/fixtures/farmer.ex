defmodule Gaia.Hub.CoopIdentity.FarmerFixtures do
  @moduledoc false

  @doc """
  Generate valid attributes for a farmer.
  """
  def valid_farmer_attrs(farm_member_id, role \\ :owner) do
    %{
      farm_member_id: farm_member_id,
      first_name: "John",
      last_name: "Doe",
      email: "john.doe@example.com",
      role: role
    }
  end
end
