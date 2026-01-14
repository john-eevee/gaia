defmodule Gaia.FarmNode.ConfigTest do
  use ExUnit.Case

  alias Gaia.FarmNode.Config
  alias Gaia.FarmNode.Config.{HubBaseUrlError, SslDirError, HttpClientError, EventDispatcherError}

  setup do
    # Reset application env after each test
    on_exit(fn ->
      Application.delete_env(:farm_node, :hub_base_url)
      Application.delete_env(:farm_node, :ssl_dir)
      Application.delete_env(:farm_node, :http_client)
      Application.delete_env(:farm_node, :event_dispatcher)
    end)
  end

  describe "validate!/0" do
    test "succeeds with valid configuration" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)

      Application.put_env(:farm_node, :event_dispatcher,
        buffer_size: 10,
        flush_interval: 5000,
        subscriptions: ["topic"]
      )

      assert Config.validate!() == :ok
    end

    test "raises HubBaseUrlError when hub_base_url is nil" do
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, [])

      assert_raise HubBaseUrlError, ~r/The :hub_base_url is missing/, fn ->
        Config.validate!()
      end
    end

    test "raises HubBaseUrlError when hub_base_url is not a string" do
      Application.put_env(:farm_node, :hub_base_url, 123)
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, [])

      assert_raise HubBaseUrlError, ~r/The :hub_base_url must be a string/, fn ->
        Config.validate!()
      end
    end

    test "raises HubBaseUrlError when hub_base_url is invalid URL" do
      Application.put_env(:farm_node, :hub_base_url, "ftp://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, [])

      assert_raise HubBaseUrlError, ~r/The :hub_base_url must be a valid absolute URL/, fn ->
        Config.validate!()
      end
    end

    test "raises SslDirError when ssl_dir is empty string" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, [])

      assert_raise SslDirError,
                   ~r/The :ssl_dir must be a string representing a directory path/,
                   fn ->
                     Config.validate!()
                   end
    end

    test "raises HttpClientError when http_client is not an atom" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, "Req")
      Application.put_env(:farm_node, :event_dispatcher, [])

      assert_raise HttpClientError, ~r/The :http_client must be a module atom/, fn ->
        Config.validate!()
      end
    end

    test "raises EventDispatcherError when event_dispatcher is not a list" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, "invalid")

      assert_raise EventDispatcherError,
                   ~r/The :event_dispatcher configuration must be a keyword list/,
                   fn ->
                     Config.validate!()
                   end
    end

    test "raises EventDispatcherError when buffer_size is not a positive integer" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, buffer_size: "10")

      assert_raise EventDispatcherError, ~r/The :buffer_size must be a positive integer/, fn ->
        Config.validate!()
      end
    end

    test "raises EventDispatcherError when buffer_size is zero" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, buffer_size: 0)

      assert_raise EventDispatcherError, ~r/The :buffer_size must be a positive integer/, fn ->
        Config.validate!()
      end
    end

    test "raises EventDispatcherError when flush_interval is not a positive integer" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, flush_interval: -1)

      assert_raise EventDispatcherError, ~r/The :flush_interval must be a positive integer/, fn ->
        Config.validate!()
      end
    end

    test "raises EventDispatcherError when subscriptions is not a list of strings" do
      Application.put_env(:farm_node, :hub_base_url, "https://example.com")
      Application.put_env(:farm_node, :ssl_dir, "priv/ssl")
      Application.put_env(:farm_node, :http_client, Req)
      Application.put_env(:farm_node, :event_dispatcher, subscriptions: [123])

      assert_raise EventDispatcherError, ~r/The :subscriptions must be a list of strings/, fn ->
        Config.validate!()
      end
    end
  end

  describe "hub_base_url/0" do
    test "returns the configured hub_base_url" do
      Application.put_env(:farm_node, :hub_base_url, "https://test.com")
      assert Config.hub_base_url() == "https://test.com"
    end

    test "returns nil when not configured" do
      assert Config.hub_base_url() == nil
    end
  end

  describe "ssl_dir/0" do
    test "returns the configured ssl_dir" do
      Application.put_env(:farm_node, :ssl_dir, "custom/ssl")
      assert Config.ssl_dir() == "custom/ssl"
    end

    test "returns default when not configured" do
      assert Config.ssl_dir() == "priv/ssl"
    end
  end

  describe "http_client/0" do
    test "returns the configured http_client" do
      Application.put_env(:farm_node, :http_client, :hackney)
      assert Config.http_client() == :hackney
    end

    test "returns default when not configured" do
      assert Config.http_client() == Req
    end
  end

  describe "event_dispatcher/0" do
    test "returns configured values" do
      Application.put_env(:farm_node, :event_dispatcher,
        buffer_size: 20,
        flush_interval: 10000,
        subscriptions: ["custom"]
      )

      result = Config.event_dispatcher()
      assert result[:buffer_size] == 20
      assert result[:flush_interval] == 10000
      assert result[:subscriptions] == ["custom"]
    end

    test "returns defaults when not configured" do
      result = Config.event_dispatcher()
      assert result[:buffer_size] == 10
      assert result[:flush_interval] == 5000
      assert result[:subscriptions] == ["telemetry:all", "event:all"]
    end

    test "returns partial defaults" do
      Application.put_env(:farm_node, :event_dispatcher, buffer_size: 15)
      result = Config.event_dispatcher()
      assert result[:buffer_size] == 15
      assert result[:flush_interval] == 5000
      assert result[:subscriptions] == ["telemetry:all", "event:all"]
    end
  end

  describe "current/0" do
    test "returns the current configuration map" do
      Application.put_env(:farm_node, :hub_base_url, "https://current.com")
      Application.put_env(:farm_node, :ssl_dir, "current/ssl")
      Application.put_env(:farm_node, :http_client, :current_client)
      Application.put_env(:farm_node, :event_dispatcher, buffer_size: 5)

      result = Config.current()
      assert result.hub_base_url == "https://current.com"
      assert result.ssl_dir == "current/ssl"
      assert result.http_client == :current_client
      assert result.event_dispatcher[:buffer_size] == 5
    end
  end
end
