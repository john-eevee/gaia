defmodule Gaia.Hub.Repo.Migrations.CreateFarmMember do
  use Ecto.Migration

  def change do
    execute("CREATE EXTENSION IF NOT EXISTS postgis;")
    create table(:farm_members, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :business_id, :string, null: false
      add :joined_at, :utc_datetime_usec, null: false

      timestamps()
    end

    execute ("SELECT AddGeometryColumn('farm_members', 'location', 4326, 'POINT', 2);")
    execute ("CREATE INDEX farm_members_location_index ON farm_members USING GIST(location);")
    execute ("ALTER TABLE farm_members ALTER COLUMN location SET NOT NULL;")
    execute ("ALTER TABLE farm_members ADD COLUMN boundaries geometry(MULTIPOLYGON, 4326);")
  end
end
