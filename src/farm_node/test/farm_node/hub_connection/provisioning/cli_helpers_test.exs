defmodule Gaia.FarmNode.HubConnection.Provisioning.CLI.HelpersTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.HubConnection.Provisioning.CLI.Helpers

  test "valid_url? returns true for http/https" do
    assert Helpers.valid_url?("https://hub.gaia.coop")
    assert Helpers.valid_url?("http://localhost:4000")
    refute Helpers.valid_url?("ftp://example")
    refute Helpers.valid_url?("not a url")
  end

  test "valid_identifier? checks format" do
    assert Helpers.valid_identifier?("green-acres")
    refute Helpers.valid_identifier?("Green")
    refute Helpers.valid_identifier?("-bad-start")
  end

  test "mask_key hides middle of long keys" do
    assert Helpers.mask_key("12345678") == "********"
    assert String.starts_with?(Helpers.mask_key("abcdefghijklmnop"), "abcd")
  end

  test "format_error handles invalid_provisioning_key" do
    assert Helpers.format_error(:invalid_provisioning_key) == "Invalid provisioning key"
  end

  test "format_error handles farm_already_provisioned" do
    assert Helpers.format_error(:farm_already_provisioned) ==
             "Farm identifier already registered with Hub"
  end

  test "format_error handles hub_request_failed" do
    error = Helpers.format_error({:hub_request_failed, :timeout})
    assert error =~ "Hub communication error"
    assert error =~ "timeout"
  end

  test "format_error handles csr_generation_failed" do
    error = Helpers.format_error({:csr_generation_failed, :bad_params})
    assert error =~ "Certificate generation error"
    assert error =~ "bad_params"
  end

  test "format_error handles storage_failed" do
    error = Helpers.format_error({:storage_failed, :permission_denied})
    assert error =~ "Storage error"
    assert error =~ "permission_denied"
  end

  test "format_error handles unknown errors" do
    error = Helpers.format_error(:unknown_error)
    assert error == ":unknown_error"
  end

  test "valid_identifier? rejects single character" do
    refute Helpers.valid_identifier?("a")
  end

  test "valid_identifier? rejects ending with dash" do
    refute Helpers.valid_identifier?("farm-")
  end

  test "valid_identifier? rejects uppercase" do
    refute Helpers.valid_identifier?("Farm-Name")
  end

  test "valid_identifier? accepts numbers in middle" do
    assert Helpers.valid_identifier?("farm-123-name")
  end

  test "mask_key handles short keys" do
    assert Helpers.mask_key("short") == "*****"
    assert Helpers.mask_key("ab") == "**"
  end

  test "mask_key reveals first 4 and last 4 of long keys" do
    masked = Helpers.mask_key("abcdefghijklmnopqrst")
    assert String.slice(masked, 0..3) == "abcd"
    assert String.slice(masked, -4..-1) == "qrst"
    # Check middle is masked
    assert String.slice(masked, 4..11) == "********"
  end
end
