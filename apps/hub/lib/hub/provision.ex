defmodule Gaia.Hub.Provision do
  @moduledoc """
  Provision module to issue certificates and access keys,
  as well as verify them for secure communications within the Hub.
  """

  alias Gaia.Hub.Provision.Diceware

  @passphrase_word_count 6

  @doc """
  Generates an access key to be used as one-time access credential.

  The generated key is a passphrase that consists of a series of
  capitalized words and numbers, giving an easy to read and type, yet secure key.
  """
  def generate_one_time_access_key() do
    Diceware.generate_passphrase(@passphrase_word_count)
  end
end
