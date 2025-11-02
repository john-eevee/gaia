defmodule Gaia.HubTest do
  use ExUnit.Case
  doctest Gaia.Hub

  test "greets the world" do
    assert Gaia.Hub.hello() == :world
  end
end
