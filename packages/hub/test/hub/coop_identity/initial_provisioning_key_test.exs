defmodule Gaia.Hub.CoopIdentity.InitialProvisioningKeyTest do
  use ExUnit.Case, async: true
  alias Ecto.Adapters.SQL.Sandbox
  alias Gaia.Hub.CoopIdentity
  alias Gaia.Hub.CoopIdentity.InitialProvisioningKey
  alias Gaia.Hub.Repo
  alias Gaia.TestingFacility.Changesets
  import Gaia.Hub.CoopIdentity.FarmFixtures
  import Gaia.Hub.CoopIdentity.InitialProvisioningKeyFixtures

  setup tags do
    pid = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end

  describe "InitialProvisioningKey.changeset/2" do
    test "should create a valid changeset with valid attributes" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_initial_provisioning_key_attrs(farm.id)

      changeset =
        InitialProvisioningKey.changeset(
          %InitialProvisioningKey{},
          Map.drop(attrs, [:plaintext_key])
        )

      assert changeset.valid?
    end

    test "should require key_hash" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)

      attrs =
        valid_initial_provisioning_key_attrs(farm.id)
        |> Map.delete(:key_hash)

      changeset =
        InitialProvisioningKey.changeset(
          %InitialProvisioningKey{},
          Map.drop(attrs, [:plaintext_key])
        )

      refute changeset.valid?
      assert %{key_hash: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should require expires_at" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)

      attrs =
        valid_initial_provisioning_key_attrs(farm.id)
        |> Map.delete(:expires_at)

      changeset =
        InitialProvisioningKey.changeset(
          %InitialProvisioningKey{},
          Map.drop(attrs, [:plaintext_key])
        )

      refute changeset.valid?
      assert %{expires_at: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should require farm_id" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)

      attrs =
        valid_initial_provisioning_key_attrs(farm.id)
        |> Map.delete(:farm_id)

      changeset =
        InitialProvisioningKey.changeset(
          %InitialProvisioningKey{},
          Map.drop(attrs, [:plaintext_key])
        )

      refute changeset.valid?
      assert %{farm_id: ["can't be blank"]} = Changesets.errors_on(changeset)
    end

    test "should default used to false" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_initial_provisioning_key_attrs(farm.id)

      changeset =
        InitialProvisioningKey.changeset(
          %InitialProvisioningKey{},
          Map.drop(attrs, [:plaintext_key])
        )

      assert Ecto.Changeset.get_field(changeset, :used) == false
    end
  end

  describe "InitialProvisioningKey.mark_as_used/1" do
    test "should mark the key as used" do
      farm = valid_farm_attrs() |> CoopIdentity.register_farm() |> elem(1)
      attrs = valid_initial_provisioning_key_attrs(farm.id)

      {:ok, key} =
        %InitialProvisioningKey{}
        |> InitialProvisioningKey.changeset(Map.drop(attrs, [:plaintext_key]))
        |> Repo.insert()

      changeset = InitialProvisioningKey.mark_as_used(key)
      assert Ecto.Changeset.get_change(changeset, :used) == true
    end
  end
end
