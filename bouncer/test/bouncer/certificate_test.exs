defmodule Gaia.Bouncer.CertificateTest do
  use ExUnit.Case, async: true

  alias Gaia.Bouncer.Certificate

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
  end
end
