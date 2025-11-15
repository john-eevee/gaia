defmodule Gaia.Bouncer.CertificateTest do
  use ExUnit.Case, async: false

  alias Gaia.Bouncer.Certificate
  alias Gaia.TestingFacility.CertificateCase

  setup_all %{} do
    Mox.defmock(Gaia.Bouncer.DatabaseMock, for: Gaia.Bouncer.Database)
    Application.put_env(:bouncer, :database_module, Gaia.Bouncer.DatabaseMock)
    :ok
  end

  describe "parse_serial/1" do
    test "returns error for invalid input" do
      assert {:error, :invalid_input} = Certificate.parse_serial(nil)
      assert {:error, :invalid_input} = Certificate.parse_serial(123)
    end

    test "returns error for invalid PEM" do
      assert {:error, :invalid_certificate} = Certificate.parse_serial("invalid pem")
      assert {:error, :invalid_certificate} = Certificate.parse_serial("")
    end

    test "returns error for malformed PEM" do
      malformed_pem = """
      -----BEGIN CERTIFICATE-----
      notbase64content
      -----END CERTIFICATE-----
      """

      assert {:error, _} = Certificate.parse_serial(malformed_pem)
    end

    test "parses serial for a valid certificate and returns uppercase hex" do
      # Create CA
      {cert, cert_pem, _} = CertificateCase.create_signed_client_certificate()
      {:ok, parsed_hex} = Certificate.parse_serial(cert_pem)
      expected = Integer.to_string(X509.Certificate.serial(cert), 16) |> String.upcase()

      assert parsed_hex == expected
    end
  end

  describe "valid?/1" do
    defp get_serial do
      {_, _, serial} = CertificateCase.create_signed_client_certificate()
      serial
    end

    test "should return unknown for unknown serial" do
      serial = get_serial()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: []}}
      end)

      assert {:ok, :unknown} = Certificate.valid?(serial)
    end

    test "should return valid for found and valid serial" do
      serial = get_serial()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[true]]}}
      end)

      assert {:ok, :valid} = Certificate.valid?(serial)
    end

    test "should return revoked for found and revoked serial" do
      serial = get_serial()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[false]]}}
      end)

      assert {:ok, :revoked} = Certificate.valid?(serial)
    end

    test "should use correct query" do
      serial = get_serial()

      expected_query = """
      SELECT status
      FROM certificate_status
      WHERE certificate_serial = $1
      LIMIT 1
      """

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn query, [^serial] ->
        assert query == expected_query
        {:ok, %{rows: []}}
      end)

      assert {:ok, :unknown} = Certificate.valid?(serial)
    end

    test "should return error on database failure" do
      serial = get_serial()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:error, :db_connection_error}
      end)

      assert {:error, :db_connection_error} = Certificate.valid?(serial)
    end

    test "should return unknown on unexpected status value" do
      serial = get_serial()

      Gaia.Bouncer.DatabaseMock
      |> Mox.expect(:query, fn _query, [^serial] ->
        {:ok, %{rows: [[nil]]}}
      end)

      assert {:ok, :unknown} = Certificate.valid?(serial)
    end
  end
end
