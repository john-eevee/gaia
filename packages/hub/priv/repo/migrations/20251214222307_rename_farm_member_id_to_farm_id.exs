defmodule Gaia.Hub.Repo.Migrations.RenameFarmMemberIdToFarmId do
  use Ecto.Migration

  def change do
    # Rename foreign key column in farmers table
    rename table(:farmers), :farm_member_id, to: :farm_id

    # Rename foreign key column in data_sharing_policies table
    rename table(:data_sharing_policies), :farm_member_id, to: :farm_id

    # Rename foreign key column in initial_provisioning_keys table
    rename table(:initial_provisioning_keys), :farm_member_id, to: :farm_id
  end
end
