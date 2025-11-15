defmodule Bouncer.PostgrexDatabaseTest do
  use ExUnit.Case

  alias Gaia.Bouncer.PostgrexDatabase

  @tag :ci
  test "should pass the query and params to postgrex functions" do
    sql = "SELECT $1 "
    params = [42]

    # We can't easily mock Postgrex here without significant setup,
    # so we'll just ensure that the function can be called without error.
    assert {:ok, %{rows: [[42]]}} = PostgrexDatabase.query(sql, params)
  end
end
