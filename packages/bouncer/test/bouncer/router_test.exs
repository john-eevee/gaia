defmodule Gaia.Bouncer.RouterTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  alias Gaia.Bouncer.Router
  alias Gaia.TestingFacility.CertificateCase

  @opts Router.init([])

  setup_all do
    Mox.defmock(Gaia.Bouncer.DatabaseMock, for: Gaia.Bouncer.Database)
    Application.put_env(:bouncer, :database_module, Gaia.Bouncer.DatabaseMock)
    {cert, cert_pem, serial} = CertificateCase.create_signed_client_certificate()
    {:ok, cert: cert, cert_pem: cert_pem, serial: serial}
  end

  describe "GET /health" do
    test "returns 200 OK" do
      conn =
        :get
        |> conn("/health")
        |> Router.call(@opts)

      assert conn.state == :sent
      assert conn.status == 200
      assert conn.resp_body == "OK"
    end
  end

  describe "unmatched routes" do
    test "returns 404 Not Found" do
      conn =
        :get
        |> conn("/unknown")
        |> Router.call(@opts)

      assert conn.state == :sent
      assert conn.status == 404
      assert conn.resp_body == "Not Found"
    end
  end

  describe "POST /validate" do
    test "returns 412 when header is missing" do
      conn =
        :post
        |> conn("/validate")
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 412 when certificate PEM is invalid" do
      conn =
        :post
        |> conn("/validate")
        |> put_req_header("x-client-cert", "invalid pem")
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 200 for valid certificate and DB shows valid", %{
      cert_pem: cert_pem,
      serial: serial
    } do
      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[true]]}}
      end)

      conn =
        :post
        |> conn("/validate")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 200
    end

    test "returns 412 when DB shows revoked", %{
      cert_pem: cert_pem,
      serial: serial
    } do
      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[false]]}}
      end)

      conn =
        :post
        |> conn("/validate")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 412 when database errors", %{
      cert_pem: cert_pem,
      serial: serial
    } do
      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:error, :db_connection_error}
      end)

      conn =
        :post
        |> conn("/validate")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 412 when serial is unknown", %{
      cert_pem: cert_pem,
      serial: serial
    } do
      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: []}}
      end)

      conn =
        :post
        |> conn("/validate")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 412
    end
  end
end
