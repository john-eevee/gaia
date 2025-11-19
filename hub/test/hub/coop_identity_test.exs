defmodule Gaia.Hub.CoopIdentityTest do
  use ExUnit.Case, async: true
  alias Gaia.Hub.CoopIdentity.FarmMemberFixtures

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Gaia.Hub.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "register_farm/1" do
    test "should insert a new farm when the attributes are valid" do
      attrs = FarmMemberFixtures.valid_farm_member_attrs()
      assert {:ok, farm_member} = Gaia.Hub.CoopIdentity.register_farm(attrs)
      assert farm_member.id != nil
    end
  end
end
