defmodule Gaia.Hub.CoopIdentity.FarmTest do
  use ExUnit.Case, async: true

  alias Gaia.Hub.CoopIdentity.Farm

  describe "farm validations" do
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

      farm_changeset = Farm.changeset(%Farm{}, attrs)
      assert farm_changeset.valid?, inspect(farm_changeset.errors)
    end

    test "should return error for invalid geometric strings" do
      attrs = %{
        name: "Test Farm",
        business_id: Ecto.UUID.generate(),
        joined_at: DateTime.utc_now(),
        location: "invalid-geojson-string"
      }

      farm_changeset = Farm.changeset(%Farm{}, attrs)
      refute farm_changeset.valid?

      assert farm_changeset.errors
             |> Enum.any?(fn error ->
               match?({:location, {"failed to decode JSON", _}}, error)
             end)
    end
  end
end
