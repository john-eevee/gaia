defmodule Gaia.FarmNode.HubConnection.Client do
  @moduledoc """
  Client for communicating with the Hub.
  The module provides API calls as functions; each public function issues requests to the Hub
  and should be invoked only when strictly necessary to ensure data protection.
  """

  @callback heartbeat() :: {:ok, Req.Response.t()} | {:error, Exception.t()}

  require Logger
  alias Gaia.FarmNode.Config
  alias Gaia.FarmNode.HubConnection.Provisioning
  alias Gaia.FarmNode.HubConnection.Client.InvalidCertificateFormat

  @doc """
  Sends a HEAD request to the heartbeat endpoint, to validate the mTLS certificate within the request.
  """

  def heartbeat do
    url = build_url("/api/v1/heartbeat")
    request(url: url, method: :head)
  end

  # see https://hexdocs.pm/req/Req.html#new/1
  defp request(options) when is_list(options) do
    default_headers = [{"user-agent", user_agent()}]

    update_headers = fn headers ->
      if List.keymember?(headers, "user-agent", 0) do
        headers
      else
        default_headers ++ headers
      end
    end

    new_options =
      options
      |> Keyword.put(:connect_options, connection_opts())
      |> Keyword.update(:headers, default_headers, update_headers)

    http_client().request(new_options)
  end

  defp http_client do
    Config.http_client()
  end

  defp build_url(path) do
    Config.hub_base_url()
    |> URI.parse()
    |> URI.append_path(path)
    |> URI.to_string()
  end

  defp user_agent() do
    version = Application.spec(:farm_node, :vsn)
    "Gaia-FarmNode/#{version}"
  end

  defp connection_opts() do
    case Provisioning.Storage.extract_ders() do
      {:ok, result} ->
        keys = result[:keys]

        [
          transport_opts: [
            cert: result[:cert],
            key: {keys[:type], keys[:key_der]},
            verify: :verify_peer,
            cacerts: :public_key.cacerts_get()
          ]
        ]

      {:error, reason} ->
        raise InvalidCertificateFormat, "Could not extract mTLS credentials: #{inspect(reason)}"
    end
  end
end
