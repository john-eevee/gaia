defmodule Gaia.Hub.ProvisionTest do
  use ExUnit.Case

  setup_all do
    # Seed random for predictable tests
    :rand.seed(:exsplus, {123, 456, 789})
    :ok
  end

  test "generate_one_time_access_key returns a passphrase with 6 words" do
    key = Gaia.Hub.Provision.generate_one_time_access_key()
    assert is_binary(key)

    words = String.split(key, "-")
    assert length(words) == 6

    Enum.each(words, fn word ->
      assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
    end)
  end
end
