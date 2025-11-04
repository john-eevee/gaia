defmodule Gaia.Hub.Provision.DicewareTest do
  use ExUnit.Case

  setup_all do
    # Seed random for predictable tests
    :rand.seed(:exsplus, {123, 456, 789})
    # NOTE: Diceware dictionary is initialized in the :hub application start
    # running with `mix test` already initializes it.
    :ok
  end

  describe "init/0" do
    test "created ETS table" do
      assert :ets.info(:diceware_dict) != :undefined
      assert :ets.info(:diceware_dict, :size) > 0
    end

    test "raises exception when called twice" do
      assert_raise Gaia.Hub.Provision.Diceware.DicewareException,
                   "Diceware dictionary already initialized, do not call init/0 twice.",
                   fn ->
                     Gaia.Hub.Provision.Diceware.init()
                   end
    end
  end

  describe "generate_passphrase/1" do
    test "with default word count" do
      passphrase = Gaia.Hub.Provision.Diceware.generate_passphrase()
      words = String.split(passphrase, "-")
      assert length(words) == 6

      Enum.each(words, fn word ->
        assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
      end)
    end

    test "with custom word count" do
      passphrase = Gaia.Hub.Provision.Diceware.generate_passphrase(4)
      words = String.split(passphrase, "-")
      assert length(words) == 4

      Enum.each(words, fn word ->
        assert String.match?(word, ~r/^[A-Z][a-z]+[1-9]$/)
      end)
    end

    test "raises error for invalid word count" do
      assert_raise FunctionClauseError, fn ->
        Gaia.Hub.Provision.Diceware.generate_passphrase(0)
      end

      assert_raise FunctionClauseError, fn ->
        Gaia.Hub.Provision.Diceware.generate_passphrase(-1)
      end
    end
  end
end
