defmodule Gaia.Hub.CoopIdentity.InitialProvisioningKeyFixtures do
  @moduledoc false

  alias Gaia.Hub.Provision

  @doc """
  Generate valid attributes for an initial provisioning key.
  """
  def valid_initial_provisioning_key_attrs(farm_id) do
    key = Provision.generate_intial_provisioning_key()
    key_hash = Provision.hash_provisioning_key(key)

    %{
      key_hash: key_hash,
      expires_at: DateTime.add(DateTime.utc_now(), 30, :day),
      farm_id: farm_id,
      plaintext_key: key
    }
  end
end
