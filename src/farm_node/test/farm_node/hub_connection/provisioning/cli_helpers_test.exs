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

  test "format_error handles variants" do
    assert Helpers.format_error(:invalid_provisioning_key) == "Invalid provisioning key"
    assert Helpers.format_error({:hub_request_failed, :timeout}) =~ "Hub communication error"
  end
end
