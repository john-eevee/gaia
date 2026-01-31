defmodule Gaia.Hub.Repo.Migrations.AddPasswordFieldsToFarmers do
  use Ecto.Migration

  def change do
    alter table(:farmers) do
      add(:password_hash, :string)
      add(:must_change_password, :boolean, default: false, null: false)
    end
  end
end