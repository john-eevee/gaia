defmodule Gaia.Hub.Repo.Migrations.CreateInitialProvisioningKeys do
  use Ecto.Migration

  def change do
    create table(:initial_provisioning_keys, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:key_hash, :string, null: false)
      add(:used, :boolean, default: false, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)

      add(
        :farm_member_id,
        references(
          :farm_members,
          type: :binary_id,
          on_delete: :delete_all
        ),
        null: false
      )

      timestamps()
    end

    create(unique_index(:initial_provisioning_keys, [:farm_member_id]))
  end
end