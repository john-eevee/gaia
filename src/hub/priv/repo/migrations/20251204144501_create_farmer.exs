defmodule Gaia.Hub.Repo.Migrations.CreateFarmer do
  use Ecto.Migration

  def up do
    execute("CREATE TYPE farmer_role AS ENUM ('owner', 'staff', 'admin');")

    create table(:farmers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :string, null: false
      add :first_name, :string, null: false
      add :last_name, :string, null: false
      add :role, :farmer_role, null: false

      add :farm_member_id,
          references(
            :farm_members,
            type: :binary_id,
            on_delete: :delete_all
          ), null: false

      timestamps()
    end

    create unique_index(:farmers, [:email])
  end

  def down do
    drop table(:farmers)
    execute("DROP TYPE farmer_role;")
  end
end
