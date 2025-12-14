defmodule Gaia.Hub.Repo.Migrations.RenameFarmMembersToFarms do
  use Ecto.Migration

  def change do
    rename table(:farm_members), to: table(:farms)
  end
end
