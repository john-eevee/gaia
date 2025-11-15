defmodule Gaia.BouncerTest do
  use ExUnit.Case
  doctest Gaia.Bouncer

  test "module exists" do
    assert Code.ensure_loaded?(Gaia.Bouncer)
  end
end
