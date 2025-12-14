defmodule Gaia.Hub.CoopIdentity.FarmFixtures do
  @moduledoc false

  def valid_farm_attrs do
    %{
      name: "Sunny Acres Farm",
      business_id: "SAF123456",
      joined_at: ~U[2024-01-15 10:00:00Z],
      location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
      boundaries:
        Geo.WKT.decode(
          "SRID=4326;MULTIPOLYGON(((-80.2 25.7, -80.2 25.8, -80.1 25.8, -80.1 25.7, -80.2 25.7)))"
        )
    }
  end
end
