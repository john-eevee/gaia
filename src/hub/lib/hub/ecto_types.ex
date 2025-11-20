Postgrex.Types.define(
  Gaia.Hub.EctoTypes,
  [Geo.PostGIS.Extension] ++ Ecto.Adapters.Postgres.extensions(),
  json: Jason
)
