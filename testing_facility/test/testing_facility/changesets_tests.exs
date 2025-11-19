defmodule Gaia.TestingFacility.ChangesetsTest do
  use ExUnit.Case, async: true
  alias Gaia.TestingFacility.Changesets

  test "should return the errors of an invalid changeset as a map" do
    import Ecto.Changeset

    data = %{}
    types = %{name: :string, age: :integer}

    changeset =
      {data, types}
      |> cast(%{name: nil, age: "not_an_integer"}, [:name, :age])
      |> validate_required([:name, :age])
      |> validate_length(:name, min: 3)

    errors = Changesets.errors_on(changeset)

    assert errors == %{
             name: ["can't be blank", "should be at least 3 character(s)"],
             age: ["is invalid"]
           }
  end
end
