defmodule Gaia.FarmNodeTest do
  use ExUnit.Case
  doctest Gaia.FarmNode

  test "greets the world" do
    assert Gaia.FarmNode.hello() == :world
  end
end
