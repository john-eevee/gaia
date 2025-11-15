defmodule Gaia.Bouncer.RouterTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plugin.Conn

  alias Gaia.Bouncer.Router

  @opts Router.init([])

  setup_all do
    Mox.defmock(Gaia.Bouncer.DatabaseMock, for: Gaia.Bouncer.Database)
    Application.put_env(:bouncer, :database_module, Gaia.Bouncer.DatabaseMock)

    :ok
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
        |> conn("/validate", "")
        |> put_req_header("x-client-cert", "invalid pem")
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 200 for valid certificate and DB shows valid" do
      # Create a client certificate signed by CA
      ca_key = X509.PrivateKey.new_rsa(2048)
      ca_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
      ca_cert = X509.Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

      client_key = X509.PrivateKey.new_rsa(2048)
      client_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")
      csr = X509.CSR.new(client_key, client_subject)

      not_before = DateTime.utc_now() |> DateTime.add(-60, :second)
      not_after = DateTime.utc_now() |> DateTime.add(365, :day)
      validity = X509.Certificate.Validity.new(not_before, not_after)

      cert =
        X509.Certificate.new(X509.CSR.public_key(csr), client_subject, ca_cert, ca_key,
          validity: validity
        )

      cert_pem = X509.Certificate.to_pem(cert)
      serial = Integer.to_string(X509.Certificate.serial(cert), 16) |> String.upcase()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[true]]}}
      end)

      conn =
        :post
        |> conn("/validate", "")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 200
    end

    test "returns 412 when DB shows revoked" do
      serial =
        :rand.uniform(100_000)
        |> Integer.to_string(16)

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[false]]}}
      end)

      # Use a certificate-like value that will parse to serial above
      # But parse_serial requires a valid PEM; reuse X509 to generate certificate with known serial
      ca_key = X509.PrivateKey.new_rsa(2048)
      ca_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
      ca_cert = X509.Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

      client_key = X509.PrivateKey.new_rsa(2048)
      client_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test/CN=test.example.com")
      csr = X509.CSR.new(client_key, client_subject)

      cert =
        X509.Certificate.new(X509.CSR.public_key(csr), client_subject, ca_cert, ca_key,
          validity: X509.Certificate.Validity.new(DateTime.utc_now(), DateTime.utc_now())
        )

      cert_pem = X509.Certificate.to_pem(cert)

      conn =
        :post
        |> conn("/validate", "")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 412
    end

    test "returns 412 when database errors" do
      serial =
        :rand.uniform(100_000)
        |> Integer.to_string(16)

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:error, :db_connection_error}
      end)

      # Generate a certificate to get serial
      ca_key = X509.PrivateKey.new_rsa(2048)
      ca_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test CA/CN=Test CA")
      ca_cert = X509.Certificate.self_signed(ca_key, ca_subject, template: :root_ca)

      client_key = X509.PrivateKey.new_rsa(2048)
      client_subject = X509.RDNSequence.new("/C=US/ST=CA/O=Test/CN=test-db-error.example.com")
      csr = X509.CSR.new(client_key, client_subject)

      cert = X509.Certificate.new(X509.CSR.public_key(csr), client_subject, ca_cert, ca_key)
      cert_pem = X509.Certificate.to_pem(cert)

      conn =
        :post
        |> conn("/validate", "")
        |> put_req_header("x-client-cert", cert_pem)
        |> Router.call(@opts)

      assert conn.status == 412
    end
  end
end
