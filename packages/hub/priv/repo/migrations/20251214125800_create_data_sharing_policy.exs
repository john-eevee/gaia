defmodule Gaia.Hub.Repo.Migrations.CreateDataSharingPolicy do
  use Ecto.Migration

  def change do
    create table(:data_sharing_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :share_anonymous_soil_data, :boolean, null: false, default: false
      add :share_pest_sightings, :boolean, null: false, default: false
      add :share_yield_data, :boolean, null: false, default: false

      add :farm_member_id,
          references(
            :farm_members,
            type: :binary_id,
            on_delete: :delete_all
          ),
          null: false

      timestamps()
    end

    create unique_index(:data_sharing_policies, [:farm_member_id])
  end
end
