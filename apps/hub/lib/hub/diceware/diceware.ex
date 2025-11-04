defmodule Gaia.Hub.Provision.Diceware do
  @moduledoc """
  Module for generating Diceware passphrases for secure access.

  """

  @diceware_wordlist_path Path.join(:code.priv_dir(:hub), "diceware/wordlist.txt")

  def init do
    if :ets.info(:diceware_dict) != :undefined do
      raise __MODULE__.DicewareException,
            "Diceware dictionary already initialized, do not call init/0 twice."
    end

    :ets.new(:diceware_dict, [:protected, :set, :named_table])

    @diceware_wordlist_path
    |> File.stream!()
    |> Stream.with_index()
    |> Stream.map(fn {line, index} ->
      word = String.trim(line)
      {index, word}
    end)
    |> Stream.each(fn entry -> :ets.insert(:diceware_dict, entry) end)
    |> Stream.run()
  end

  @doc """
  Generates a Diceware passphrase consisting of the specified number of words.

  ## Parameters
    - word_count: The number of words to include in the passphrase (default is 6).

  ## Returns
    - A string representing the generated passphrase.

  """
  def generate_passphrase(word_count \\ 6) when word_count > 0 do
    word_count
    |> get_n_words()
    |> Enum.map(fn word ->
      number = :rand.uniform(9)
      capitalized_word = String.capitalize(word)
      "#{capitalized_word}#{number}"
    end)
    |> Enum.join("-")
  end

  defp get_n_words(n) do
    size = :ets.info(:diceware_dict, :size)

    Enum.map(1..n, fn _ ->
      index = :rand.uniform(size) - 1
      [{_, word}] = :ets.lookup(:diceware_dict, index)
      word
    end)
  end

  defmodule DicewareException do
    defexception message: "Diceware exception occurred"

    def exception(message) do
      %DicewareException{message: message}
    end
  end
end
