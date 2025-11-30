defmodule Gaia.Hub.CoopIdentity.FarmMemberTest do
  use ExUnit.Case, async: true

  alias Gaia.TestingFacility.Changesets
  alias Gaia.Hub.CoopIdentity.FarmMember

  describe "farm member validations" do
    test "should be cast from geometric strings" do
      attrs = %{
        name: "Test Farm",
        business_id: Ecto.UUID.generate(),
        joined_at: DateTime.utc_now(),
        location: ~s({
          "type": "Feature",
          "geometry": {
            "type": "Point",
            "coordinates": [125.6, 10.1]
          }
        })
      }

      farm_member_changeset = FarmMember.changeset(%FarmMember{}, attrs)
      assert farm_member_changeset.valid?, inspect(farm_member_changeset.errors)
    end

    test "should return error for invalid geometric strings" do
      attrs = %{
        name: "Test Farm",
        business_id: Ecto.UUID.generate(),
        joined_at: DateTime.utc_now(),
        location: "invalid-geojson-string"
      }

      farm_member_changeset = FarmMember.changeset(%FarmMember{}, attrs)
      refute farm_member_changeset.valid?

      assert farm_member_changeset.errors
             |> Enum.any?(fn error ->
               match?({:location, {"failed to decode JSON", _}}, error)
             end)
    end
  end
end
