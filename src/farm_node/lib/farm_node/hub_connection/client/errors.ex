defmodule Gaia.FarmNode.HubConnection.Client.UrlMissingError do
  defexception message: "Hub base URL is missing in the application configuration"
end

defmodule Gaia.FarmNode.HubConnection.Client.InvalidUrlError do
  defexception message: "Hub base URL is invalid"

  @impl true
  def exception(url) when is_binary(url) do
    %__MODULE__{message: "Hub base URL is invalid: #{url}"}
  end

  def exception(_) do
    %__MODULE__{}
  end
end

defmodule Gaia.FarmNode.HubConnection.Client.NotProvisionedError do
  defexception message: "Node has not been provisioned with mTLS credentials"
end
