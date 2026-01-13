defmodule Gaia.FarmNode.HubConnection.Client do
  @moduledoc """
  Client for communicating with the Hub.
  The module provides API calls as functions; each public function issues requests to the Hub
  and should be invoked only when strictly necessary to ensure data protection.
  """
  require Logger
  alias Gaia.FarmNode.HubConnection.Client.InvalidUrlError
  alias Gaia.FarmNode.HubConnection.Client.NotProvisionedError
  alias Gaia.FarmNode.HubConnection.Client.UrlMissingError
  alias Gaia.FarmNode.HubConnection.Provisioning

  def heartbeat() do
    with {:ok, url} <- build_url("/api/v1/heartbeat") do
      request(url: url)
    end
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

  # undocumented application configuration
  # used only for testing purposes, we only support one http library, since
  # we need to configure it's connection and each have their own way.
  defp http_client() do
    case Application.get_env(:farm_node, __MODULE__) do
      [http_client: client] when is_atom(client) -> client
      _ -> Req
    end
  end

  defp build_url(path) do
    with {:ok, url} <- base_url() do
      full_url =
        url
        |> URI.parse()
        |> URI.append_path(path)
        |> URI.to_string()

      {:ok, full_url}
    end
  end

  defp base_url() do
    case Application.get_env(:farm_node, __MODULE__) do
      [base_url: base_url] -> validate_url(base_url)
      _ -> {:error, %UrlMissingError{}}
    end
  end

  defp validate_url(base_url) do
    valid_scheme = fn scheme ->
      Enum.find([:https, :http], fn
        ^scheme -> true
        _ -> false
      end)
    end

    is_uri = fn ->
      uri = URI.parse(base_url)
      is_binary(uri.host) && valid_scheme.(uri.scheme)
    end

    if is_uri.() do
      {:ok, base_url}
    else
      {:error, InvalidUrlError.exception(base_url)}
    end
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
        raise NotProvisionedError, "Could not extract mTLS credentials: #{inspect(reason)}"
    end
  end
end
