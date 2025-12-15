defmodule Gaia.Hub.CoopIdentity.FarmerTest do
  use ExUnit.Case, async: true
  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.Repo
  alias Gaia.Hub.CoopIdentity.Farmer
  alias Gaia.Hub.CoopIdentity
  import Gaia.Hub.CoopIdentity.FarmFixtures
  import Gaia.TestingFacility.Changesets

  setup tags do
    pid = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "changeset/2" do
    setup do
      attrs = valid_farm_attrs()
      {:ok, farm} = CoopIdentity.register_farm(attrs)
      %{farm: farm}
    end

    test "valid attributes", %{farm: farm} do
      attrs = %{
        email: "farmer@example.com",
        first_name: "John",
        last_name: "Doe",
        role: :owner,
        farm_id: farm.id
      }

      changeset = Farmer.changeset(%Farmer{}, attrs)
      assert changeset.valid?
    end

    test "invalid attributes" do
      attrs = %{
        email: nil,
        first_name: nil,
        last_name: nil,
        role: nil,
        farm_id: nil
      }

      changeset = Farmer.changeset(%Farmer{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).email
      assert "can't be blank" in errors_on(changeset).first_name
      assert "can't be blank" in errors_on(changeset).last_name
      assert "can't be blank" in errors_on(changeset).role
      assert "can't be blank" in errors_on(changeset).farm_id
    end

    test "invalid role", %{farm: farm} do
      attrs = %{
        email: "farmer@example.com",
        first_name: "John",
        last_name: "Doe",
        role: :invalid_role,
        farm_id: farm.id
      }

      changeset = Farmer.changeset(%Farmer{}, attrs)
      refute changeset.valid?
      assert "is invalid" in errors_on(changeset).role
    end

    test "unique email constraint", %{farm: farm} do
      attrs = %{
        email: "farmer@example.com",
        first_name: "John",
        last_name: "Doe",
        role: :owner,
        farm_id: farm.id
      }

      {:ok, _farmer} =
        %Farmer{}
        |> Farmer.changeset(attrs)
        |> Repo.insert()

      assert {:error, changeset} =
               %Farmer{}
               |> Farmer.changeset(attrs)
               |> Repo.insert()

      assert "has already been taken" in errors_on(changeset).email
    end

    test "foreign key constraint violation" do
      attrs = %{
        email: "farmer@example.com",
        first_name: "John",
        last_name: "Doe",
        role: :owner,
        farm_id: Ecto.UUID.generate()
      }

      assert_raise Ecto.ConstraintError, fn ->
        %Farmer{}
        |> Farmer.changeset(attrs)
        |> Repo.insert()
      end
    end
  end
end
