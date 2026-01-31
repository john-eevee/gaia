defmodule Gaia.Hub.Provision.KeyHash do
  @moduledoc """
  Module responsible for hashing and verifying provisioning keys.
  """

  @type t :: module()

  @callback hash(raw :: String.t()) :: String.t()
  @callback verify(provided_hash :: String.t(), expected :: String.t()) :: boolean()

  defmodule Argon do
    @moduledoc """
    Implementation of the `Gaia.Hub.Provision.KeyHash` behaviour using Argon2.
    The default configuration of Argon2 is to use argon2id.
    """
    @behaviour Gaia.Hub.Provision.KeyHash

    @impl true
    def hash(key) when is_binary(key) do
      Argon2.hash_pwd_salt(key)
    end

    @impl true
    def verify(provided_hash, expected)
        when is_binary(provided_hash) and is_binary(expected) do
      Argon2.verify_pass(expected, provided_hash)
    rescue
      ArgumentError -> false
    end
  end
end
