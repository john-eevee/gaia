defmodule Gaia.FarmNode.HubConnection.Provisioning.Client do
  @moduledoc """
  HTTP client for communicating with the Hub's provisioning endpoint.

  This module handles the initial handshake where the Farm Node:
  1. Sends its CSR and provisioning key to the Hub
  2. Receives a signed certificate in return
  3. Validates the response
  """

  require Logger

  @provisioning_endpoint "/api/v1/provision"
  @timeout 30_000

  @doc """
  Sends a provisioning request to the Hub.

  ## Parameters
  - `hub_address`: The base URL of the Hub (e.g., "https://hub.gaia.coop")
  - `provisioning_key`: The initial shared secret for authentication
  - `csr_pem`: The Certificate Signing Request in PEM format
  - `farm_identifier`: A unique identifier for this farm node

  ## Returns
  - `{:ok, certificate_pem}` on success
  - `{:error, reason}` on failure
  """
  def request_provisioning(hub_address, provisioning_key, csr_pem, farm_identifier) do
    url = build_url(hub_address, @provisioning_endpoint)

    body = %{
      provisioning_key: provisioning_key,
      csr: csr_pem,
      farm_identifier: farm_identifier,
      node_version: Application.spec(:farm_node, :vsn) |> to_string()
    }

    Logger.info("Sending provisioning request to #{url}")

    with {:ok, json} <- Jason.encode(body),
         {:ok, response} <- make_request(url, json),
         {:ok, certificate} <- parse_response(response) do
      Logger.info("Successfully received mTLS certificate from Hub")
      {:ok, certificate}
    else
      {:error, reason} = error ->
        Logger.error("Provisioning failed: #{inspect(reason)}")
        error
    end
  end

  # Private Functions

  defp build_url(hub_address, path) do
    # Normalize hub_address (remove trailing slash if present)
    base = String.trim_trailing(hub_address, "/")
    "#{base}#{path}"
  end

  defp make_request(url, json_body) do
    headers = [
      {"content-type", "application/json"},
      {"user-agent", "Gaia-FarmNode/0.1.0"}
    ]

    # Allow injection of a test HTTP client via application config for
    # deterministic testing. Defaults to Req in production.
    http_client = Application.get_env(:farm_node, :http_client, Req)

    case http_client.post(url,
           body: json_body,
           headers: headers,
           receive_timeout: @timeout,
           retry: false
         ) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: 401}} ->
        {:error, :invalid_provisioning_key}

      {:ok, %{status: 409}} ->
        {:error, :farm_already_provisioned}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, exception} ->
        {:error, {:request_failed, exception}}
    end
  end

  defp parse_response(body) when is_map(body) do
    case body do
      %{"certificate" => cert} when is_binary(cert) ->
        {:ok, cert}

      %{"error" => error} ->
        {:error, {:hub_error, error}}

      _ ->
        {:error, :invalid_response_format}
    end
  end

  defp parse_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_response(decoded)
      {:error, _} -> {:error, :invalid_json_response}
    end
  end
end
