defmodule GaiaLibTest do
  use ExUnit.Case
  doctest GaiaLib

  test "greets the world" do
    assert GaiaLib.hello() == :world
  end
end
