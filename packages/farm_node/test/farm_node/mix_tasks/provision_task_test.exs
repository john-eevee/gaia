defmodule Mix.Tasks.FarmNode.ProvisionTest do
  use ExUnit.Case, async: false

  setup do
    Application.ensure_all_started(:farm_node)
    :ok
  end

  test "provision mix task runs non-interactively with --yes" do
    # Prepare an HTTP client that returns a valid cert PEM
    defmodule TestHttpClient do
      def post(_url, _opts) do
        key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(key, "/CN=hub-test")
        {:ok, %{status: 200, body: %{"certificate" => X509.Certificate.to_pem(cert)}}}
      end
    end

    Application.put_env(:farm_node, :http_client, TestHttpClient)

    Mix.Tasks.FarmNode.Provision.run([
      "--hub-address",
      "https://hub",
      "--provisioning-key",
      "k",
      "--farm-identifier",
      "mix-farm",
      "--yes"
    ])

    Application.delete_env(:farm_node, :http_client)
  end
end
