defmodule Gaia.FarmNode.HubConnection.Provisioning.CliErrorsTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "run/1 surfaces hub communication errors" do
    defmodule TestHttpClient401 do
      def post(_url, _opts), do: {:ok, %{status: 401}}
    end

    Application.put_env(:farm_node, :http_client, TestHttpClient401)

    capture = capture_io(fn ->
      result = CLI.run(hub_address: "https://hub", provisioning_key: "k", farm_identifier: "f", skip_confirmation: true)
      assert {:error, {:hub_request_failed, :invalid_provisioning_key}} = result
    end)

    assert capture =~ "Provisioning Failed" or capture =~ "Invalid provisioning key"

    Application.delete_env(:farm_node, :http_client)
  end

  test "run/1 surfaces http server errors" do
    defmodule TestHttpClient500 do
      def post(_url, _opts), do: {:ok, %{status: 500, body: "server error"}}
    end

    Application.put_env(:farm_node, :http_client, TestHttpClient500)

    capture = capture_io(fn ->
      result = CLI.run(hub_address: "https://hub", provisioning_key: "k", farm_identifier: "f", skip_confirmation: true)
      assert {:error, {:hub_request_failed, {:http_error, 500, "server error"}}} = result
    end)

    assert capture =~ "Provisioning Failed"

    Application.delete_env(:farm_node, :http_client)
  end
end
