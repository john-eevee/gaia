defmodule Gaia.Hub.CoopIdentityTest do
  use ExUnit.Case, async: true
  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.CoopIdentity
  alias Gaia.Hub.CoopIdentity.InitialProvisioningKey
  alias Gaia.Hub.Repo
  alias Gaia.Hub.Provision
  alias Gaia.TestingFacility.Changesets
  import Gaia.Hub.CoopIdentity.FarmMemberFixtures
  import Gaia.Hub.CoopIdentity.FarmerFixtures

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
      farm_with_policy = Repo.preload(farm_member, :data_sharing_policy)

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

    test "should return error when missing required attributes" do
      # Test missing business_id
      attrs = valid_farm_member_attrs() |> Map.delete(:business_id)
      assert {:error, changeset} = CoopIdentity.register_farm(attrs)
      assert %{business_id: ["can't be blank"]} = Changesets.errors_on(changeset)

      # Test missing location
      attrs = valid_farm_member_attrs() |> Map.delete(:location)
      assert {:error, changeset} = CoopIdentity.register_farm(attrs)
      assert %{location: ["can't be blank"]} = Changesets.errors_on(changeset)
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

    test "should return error when missing required attributes" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      # Test missing first_name
      attrs = valid_farmer_attrs(farm_member.id) |> Map.delete(:first_name)
      assert {:error, changeset} = CoopIdentity.register_farmer(attrs)
      assert %{first_name: ["can't be blank"]} = Changesets.errors_on(changeset)

      # Test missing last_name
      attrs = valid_farmer_attrs(farm_member.id) |> Map.delete(:last_name)
      assert {:error, changeset} = CoopIdentity.register_farmer(attrs)
      assert %{last_name: ["can't be blank"]} = Changesets.errors_on(changeset)
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

    test "should log all changes made to policy" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      # Make multiple changes at once to verify logging
      assert {:ok, policy} =
               CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
                 share_pest_sightings: true,
                 share_yield_data: true,
                 share_anonymous_soil_data: true
               })

      assert policy.share_pest_sightings == true
      assert policy.share_yield_data == true
      assert policy.share_anonymous_soil_data == true
    end

    test "should handle no changes gracefully" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)

      # Enable all fields
      {:ok, _} =
        CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
          share_pest_sightings: true,
          share_yield_data: true,
          share_anonymous_soil_data: true
        })

      # Try to set them to the same values (no actual changes)
      assert {:ok, policy} =
               CoopIdentity.toggle_data_sharing_policy(farm_member.id, %{
                 share_pest_sightings: true,
                 share_yield_data: true,
                 share_anonymous_soil_data: true
               })

      assert policy.share_pest_sightings == true
      assert policy.share_yield_data == true
      assert policy.share_anonymous_soil_data == true
    end
  end

  describe "add_new_farm_member/1" do
    test "should create farm member, farmer, provisioning key, and data sharing policy" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "john@greenvalley.com",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:ok, result} = CoopIdentity.add_new_farm_member(attrs)

      # Verify farm member was created
      assert result.farm_member.id != nil
      assert result.farm_member.name == "Green Valley Farm"
      assert result.farm_member.business_id == "GVF123"

      # Verify farmer was created
      assert result.farmer.id != nil
      assert result.farmer.email == "john@greenvalley.com"
      assert result.farmer.first_name == "John"
      assert result.farmer.last_name == "Smith"
      assert result.farmer.role == :owner
      assert result.farmer.farm_member_id == result.farm_member.id

      # Verify farmer has password fields set correctly
      assert result.farmer.password_hash != nil
      assert result.farmer.must_change_password == true

      # Verify provisioning key and password are returned
      assert is_binary(result.provisioning_key)
      assert String.contains?(result.provisioning_key, "-")
      assert is_binary(result.disposable_password)
      assert String.contains?(result.disposable_password, "-")

      # Verify provisioning key was stored in database
      provisioning_key =
        Repo.get_by(InitialProvisioningKey, farm_member_id: result.farm_member.id)

      assert provisioning_key != nil
      assert provisioning_key.used == false
      assert Provision.provisioning_key_valid?(provisioning_key.key_hash, result.provisioning_key)

      # Verify farmer password hash is valid
      assert Provision.provisioning_key_valid?(
               result.farmer.password_hash,
               result.disposable_password
             )

      # Verify data sharing policy was created with all sharing disabled
      farm_with_policy = Repo.preload(result.farm_member, :data_sharing_policy)
      policy = farm_with_policy.data_sharing_policy
      assert policy != nil
      assert policy.share_anonymous_soil_data == false
      assert policy.share_pest_sightings == false
      assert policy.share_yield_data == false
    end

    test "should return error when farm attributes are invalid" do
      attrs = %{
        farm_name: "",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "john@greenvalley.com",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:error, changeset} = CoopIdentity.add_new_farm_member(attrs)
      assert %{name: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should return error when farmer attributes are invalid" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "invalid-email",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:error, changeset} = CoopIdentity.add_new_farm_member(attrs)
      assert %{email: ["must have the @ sign and no spaces"]} = Changesets.errors_on(changeset)
    end

    test "should set provisioning key expiration to 30 days from now" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "john@greenvalley.com",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:ok, result} = CoopIdentity.add_new_farm_member(attrs)

      provisioning_key =
        Repo.get_by(InitialProvisioningKey, farm_member_id: result.farm_member.id)

      now = DateTime.utc_now()
      expected_expiry = DateTime.add(now, 30, :day)

      # Allow 5 second tolerance for test execution time
      assert DateTime.diff(provisioning_key.expires_at, expected_expiry, :second) |> abs() < 5
    end

    test "should create farmer with must_change_password set to true" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "john@greenvalley.com",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:ok, result} = CoopIdentity.add_new_farm_member(attrs)
      assert result.farmer.must_change_password == true
    end

    test "should support different farmer roles" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        farmer_email: "admin@greenvalley.com",
        farmer_first_name: "Jane",
        farmer_last_name: "Doe",
        farmer_role: :admin
      }

      assert {:ok, result} = CoopIdentity.add_new_farm_member(attrs)
      assert result.farmer.role == :admin
    end

    test "should support optional boundaries" do
      attrs = %{
        farm_name: "Green Valley Farm",
        business_id: "GVF123",
        location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
        boundaries:
          Geo.WKT.decode(
            "SRID=4326;MULTIPOLYGON(((-80.2 25.7, -80.2 25.8, -80.1 25.8, -80.1 25.7, -80.2 25.7)))"
          ),
        farmer_email: "john@greenvalley.com",
        farmer_first_name: "John",
        farmer_last_name: "Smith",
        farmer_role: :owner
      }

      assert {:ok, result} = CoopIdentity.add_new_farm_member(attrs)
      assert result.farm_member.boundaries != nil
    end
  end
end
