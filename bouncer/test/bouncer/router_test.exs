defmodule Gaia.Bouncer.RouterTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Gaia.Bouncer.Router

  @opts Router.init([])

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
end
