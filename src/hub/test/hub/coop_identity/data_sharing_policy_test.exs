defmodule Gaia.Hub.CoopIdentity.DataSharingPolicyTest do
  use ExUnit.Case, async: true

  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.CoopIdentity
  alias Gaia.Hub.CoopIdentity.DataSharingPolicy
  alias Gaia.Hub.Repo
  alias Gaia.TestingFacility.Changesets
  import Gaia.Hub.CoopIdentity.FarmMemberFixtures
  import Gaia.Hub.CoopIdentity.DataSharingPolicyFixtures

  setup tags do
    pid = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "data sharing policy validations" do
    test "should require farm_member_id" do
      attrs = %{
        share_anonymous_soil_data: false,
        share_pest_sightings: false,
        share_yield_data: false
      }

      changeset = DataSharingPolicy.changeset(%DataSharingPolicy{}, attrs)
      refute changeset.valid?
      assert %{farm_member_id: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should accept valid attributes with all defaults" do
      farm_member = valid_farm_member_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_data_sharing_policy_attrs(farm_member.id)

      changeset = DataSharingPolicy.changeset(%DataSharingPolicy{}, attrs)
      assert changeset.valid?
    end

    test "should have all sharing fields default to false" do
      policy = %DataSharingPolicy{}
      assert policy.share_anonymous_soil_data == false
      assert policy.share_pest_sightings == false
      assert policy.share_yield_data == false
    end
  end
end
