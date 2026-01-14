defmodule Gaia.FarmNode.HubConnection.Client.NotProvisionedError do
  @moduledoc """
  Exception raised when the node attempts Hub communication without mTLS credentials.
  """
  defexception message: "Node has not been provisioned with mTLS credentials"
end
