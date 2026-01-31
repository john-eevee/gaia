defmodule Gaia.FarmNode.HubConnection.Provisioning.CLI.Helpers do
  @moduledoc false

  def valid_url?(url) do
    uri = URI.parse(url)
    uri.scheme in ["http", "https"] and uri.host != nil
  end

  def valid_identifier?(identifier) do
    Regex.match?(~r/^[a-z0-9][a-z0-9\-]*[a-z0-9]$/, identifier)
  end

  def mask_key(key) when is_binary(key) do
    len = String.length(key)

    if len <= 8 do
      String.duplicate("*", len)
    else
      String.slice(key, 0..3) <> String.duplicate("*", len - 8) <> String.slice(key, -4..-1)
    end
  end

  def format_error(:invalid_provisioning_key), do: "Invalid provisioning key"
  def format_error(:farm_already_provisioned), do: "Farm identifier already registered with Hub"

  def format_error({:hub_request_failed, reason}),
    do: "Hub communication error: #{inspect(reason)}"

  def format_error({:csr_generation_failed, reason}),
    do: "Certificate generation error: #{inspect(reason)}"

  def format_error({:storage_failed, reason}), do: "Storage error: #{inspect(reason)}"
  def format_error(reason), do: inspect(reason)
end
