defmodule Gaia.Hub.CoopIdentityTest do
  use ExUnit.Case, async: true
  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.CoopIdentity
  alias Gaia.Hub.Repo
  alias Gaia.TestingFacility.Changesets
  import Gaia.Hub.CoopIdentity.FarmMemberFixtures
  import Gaia.Hub.CoopIdentity.FarmerFixtures
  import Gaia.Hub.CoopIdentity.DataSharingPolicyFixtures

  setup tags do
    pid = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "register_farm/1" do
    test "should insert a new farm when the attributes are valid" do
      attrs = valid_farm_member_attrs()
      assert {:ok, farm_member} = CoopIdentity.register_farm(attrs)
      assert farm_member.id != nil
    end

    test "should return a changeset with errors when attributes are invalid" do
      attrs = valid_farm_member_attrs() |> Map.delete(:name)
      assert {:error, changeset} = CoopIdentity.register_farm(attrs)
      assert %{name: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should automatically create a data sharing policy with all fields set to false" do
      attrs = valid_farm_member_attrs()
      assert {:ok, farm_member} = CoopIdentity.register_farm(attrs)

      # Load the associated data sharing policy
      farm_with_policy =
        Repo.preload(farm_member, :data_sharing_policy)

      assert farm_with_policy.data_sharing_policy != nil
      assert farm_with_policy.data_sharing_policy.share_anonymous_soil_data == false
      assert farm_with_policy.data_sharing_policy.share_pest_sightings == false
      assert farm_with_policy.data_sharing_policy.share_yield_data == false
    end

    test "should demonstrate that data concepts are not shared by default" do
      attrs = valid_farm_member_attrs()
      assert {:ok, farm_member} = CoopIdentity.register_farm(attrs)

      farm_with_policy = Repo.preload(farm_member, :data_sharing_policy)
      policy = farm_with_policy.data_sharing_policy

      # Verify no data is shared by default
      refute policy.share_anonymous_soil_data, "Soil data should NOT be shared by default"
      refute policy.share_pest_sightings, "Pest sightings should NOT be shared by default"
      refute policy.share_yield_data, "Yield data should NOT be shared by default"
    end
  end

  describe "register_farmer/1" do
    test "should insert a farmer for the given farm when the attributes are valid" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_farmer_attrs(farm_member.id)
      assert {:ok, farmer} = CoopIdentity.register_farmer(attrs)
      assert farmer.id != nil
      assert farmer.farm_member_id == farm_member.id
    end

    test "should return a changeset with errors when attributes are invalid" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_farmer_attrs(farm_member.id) |> Map.put(:email, "")
      assert {:error, changeset} = CoopIdentity.register_farmer(attrs)
      assert %{email: ["can't be blank"]} = Changesets.errors_on(changeset)
    end
  end

  describe "toggle_data_sharing_policy/2" do
    test "should update a single policy field" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      assert {:ok, policy} =
               CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
                 share_pest_sightings: true
               })

      assert policy.share_pest_sightings == true
      assert policy.share_anonymous_soil_data == false
      assert policy.share_yield_data == false
    end

    test "should update multiple policy fields" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      assert {:ok, policy} =
               CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
                 share_pest_sightings: true,
                 share_yield_data: true
               })

      assert policy.share_pest_sightings == true
      assert policy.share_yield_data == true
      assert policy.share_anonymous_soil_data == false
    end

    test "should toggle a field from true back to false" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      # First enable it
      {:ok, _} =
        CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
          share_anonymous_soil_data: true
        })

      # Then disable it
      assert {:ok, policy} =
               CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
                 share_anonymous_soil_data: false
               })

      assert policy.share_anonymous_soil_data == false
    end

    test "should return error when farm member does not exist" do
      non_existent_id = Ecto.UUID.generate()

      assert {:error, :not_found} =
               CoopIdentity.toggle_data_sharing_policy(non_existent_id, %{
                 share_pest_sightings: true
               })
    end
  end
end
