defmodule Gaia.FarmNode.HubConnection.Provisioning.ClientTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.HubConnection.Provisioning.Client

  # Define the HTTP client behavior for mocking
  defmodule HttpClientBehaviour do
    @callback post(url :: binary, opts :: keyword) ::
                {:ok, %{status: non_neg_integer, body: any}} | {:error, any}
  end

  Mox.defmock(MockHttpClient, for: HttpClientBehaviour)

  setup do
    # Set up the mock for the test
    Application.put_env(:farm_node, :http_client, MockHttpClient)

    on_exit(fn ->
      Application.delete_env(:farm_node, :http_client)
    end)

    :ok
  end

  test "request_provisioning returns certificate on 200" do
    Mox.expect(MockHttpClient, :post, fn _url, opts ->
      body = Jason.decode!(opts[:body])
      {:ok, %{status: 200, body: %{"certificate" => "CERT_PEM"}}}
    end)

    assert {:ok, "CERT_PEM"} =
             Client.request_provisioning("https://hub", "key", "ok-case", "farm")

    Mox.verify!()
  end

  test "request_provisioning returns error for 401" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:ok, %{status: 401}}
    end)

    assert {:error, :invalid_provisioning_key} =
             Client.request_provisioning("https://hub", "key", "401-case", "farm")

    Mox.verify!()
  end

  test "request_provisioning returns farm already registered for 409" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:ok, %{status: 409}}
    end)

    assert {:error, :farm_already_provisioned} =
             Client.request_provisioning("https://hub", "key", "409-case", "farm")

    Mox.verify!()
  end

  test "request_provisioning surfaces http errors" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:ok, %{status: 500, body: "server error"}}
    end)

    assert {:error, {:http_error, 500, "server error"}} =
             Client.request_provisioning("https://hub", "key", "500-case", "farm")

    Mox.verify!()
  end

  test "request_provisioning surfaces request failures" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:error, :conn_refused}
    end)

    assert {:error, {:request_failed, :conn_refused}} =
             Client.request_provisioning("https://hub", "key", "huh", "farm")

    Mox.verify!()
  end

  test "request_provisioning handles map body responses" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:error, %{status: 200, body: %{"error" => "bad request"}}}
    end)

    assert {:error, {:request_failed, %{status: 200, body: %{"error" => "bad request"}}}} =
             Client.request_provisioning("https://hub", "key", "bad-body", "farm")

    Mox.verify!()
  end

  test "request_provisioning accepts JSON string body responses" do
    Mox.expect(MockHttpClient, :post, fn _url, _opts ->
      {:ok, %{status: 200, body: Jason.encode!(%{"certificate" => "CERT_AS_STRING"})}}
    end)

    assert {:ok, "CERT_AS_STRING"} =
             Client.request_provisioning("https://hub", "key", "any", "farm")

    Mox.verify!()
  end
end
