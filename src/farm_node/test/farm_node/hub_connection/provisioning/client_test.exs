defmodule Gaia.FarmNode.HubConnection.Provisioning.ClientTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.HubConnection.Provisioning.Client

  setup do
    # Backup and clear any http_client config to avoid interfering with other tests
    orig = Application.get_env(:farm_node, :http_client)

    on_exit(fn ->
      if orig == nil do
        Application.delete_env(:farm_node, :http_client)
      else
        Application.put_env(:farm_node, :http_client, orig)
      end
    end)

    :ok
  end

  defmodule TestHttpClient do
    def post(_url, opts) do
      # The body is JSON encoded by the client; decode and match on csr
      body = opts[:body]

      case Jason.decode(body) do
        {:ok, %{"csr" => "ok-case"}} ->
          {:ok, %{status: 200, body: %{"certificate" => "CERT_PEM"}}}

        {:ok, %{"csr" => "401-case"}} ->
          {:ok, %{status: 401}}

        {:ok, %{"csr" => "409-case"}} ->
          {:ok, %{status: 409}}

        {:ok, %{"csr" => "500-case"}} ->
          {:ok, %{status: 500, body: "server error"}}

        _ ->
          {:error, :conn_refused}
      end
    end
  end

  test "request_provisioning returns certificate on 200" do
    Application.put_env(:farm_node, :http_client, TestHttpClient)

    assert {:ok, "CERT_PEM"} =
             Client.request_provisioning("https://hub", "key", "ok-case", "farm")
  end

  test "request_provisioning returns error for 401" do
    Application.put_env(:farm_node, :http_client, TestHttpClient)

    assert {:error, :invalid_provisioning_key} =
             Client.request_provisioning("https://hub", "key", "401-case", "farm")
  end

  test "request_provisioning returns farm already registered for 409" do
    Application.put_env(:farm_node, :http_client, TestHttpClient)

    assert {:error, :farm_already_provisioned} =
             Client.request_provisioning("https://hub", "key", "409-case", "farm")
  end

  test "request_provisioning surfaces http errors" do
    Application.put_env(:farm_node, :http_client, TestHttpClient)

    assert {:error, {:http_error, 500, "server error"}} =
             Client.request_provisioning("https://hub", "key", "500-case", "farm")
  end

  test "request_provisioning surfaces request failures" do
    Application.put_env(:farm_node, :http_client, TestHttpClient)

    assert {:error, {:request_failed, :conn_refused}} =
             Client.request_provisioning("https://hub", "key", "bad-body", "farm")
  end

  defmodule TestHttpClientStringBody do
    def post(_url, _opts) do
      {:ok, %{status: 200, body: Jason.encode!(%{"certificate" => "CERT_AS_STRING"})}}
    end
  end

  test "request_provisioning accepts JSON string body responses" do
    Application.put_env(:farm_node, :http_client, TestHttpClientStringBody)

    assert {:ok, "CERT_AS_STRING"} =
             Client.request_provisioning("https://hub", "key", "any", "farm")
  end
end
