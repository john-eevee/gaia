defmodule Gaia.Hub.CoopIdentityTest do
  use ExUnit.Case, async: true
  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.CoopIdentity
  alias Gaia.Hub.Repo
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
end
