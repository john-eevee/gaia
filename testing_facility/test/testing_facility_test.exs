defmodule TestingFacilityTest do
  use ExUnit.Case
  doctest TestingFacility

  test "greets the world" do
    assert TestingFacility.hello() == :world
  end
end
