defmodule Gaia.Hub.CoopIdentityTest do
  use ExUnit.Case, async: true
  alias Gaia.TestingFacility.Changesets
  import Gaia.Hub.CoopIdentity.FarmMemberFixtures

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Gaia.Hub.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "register_farm/1" do
    test "should insert a new farm when the attributes are valid" do
      attrs = valid_farm_member_attrs()
      assert {:ok, farm_member} = Gaia.Hub.CoopIdentity.register_farm(attrs)
      assert farm_member.id != nil
    end

    test "should return a changeset with errors when attributes are invalid" do
      attrs = valid_farm_member_attrs() |> Map.delete(:name)
      assert {:error, changeset} = Gaia.Hub.CoopIdentity.register_farm(attrs)
      assert %{name: ["can't be blank"]} = Changesets.errors_on(changeset)
    end
  end
end
