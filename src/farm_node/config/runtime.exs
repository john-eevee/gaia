import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or external sources.

if config_env() == :prod do
  hub_base_url =
    System.get_env("HUB_BASE_URL") ||
      raise """
      environment variable HUB_BASE_URL is missing.
      This is required for the Farm Node to connect to the central Hub.
      """

  ssl_dir = System.get_env("SSL_DIR") || "priv/ssl"

  config :farm_node,
    hub_base_url: hub_base_url,
    ssl_dir: ssl_dir

  # Example of configuring the event dispatcher via ENV at runtime
  buffer_size = System.get_env("EVENT_BUFFER_SIZE")
  flush_interval = System.get_env("EVENT_FLUSH_INTERVAL")

  if buffer_size || flush_interval do
    current_config = Application.get_env(:farm_node, :event_dispatcher, [])

    new_config =
      current_config
      |> Keyword.update(:buffer_size, 10, fn current ->
        if buffer_size, do: String.to_integer(buffer_size), else: current
      end)
      |> Keyword.update(:flush_interval, 5000, fn current ->
        if flush_interval, do: String.to_integer(flush_interval), else: current
      end)

    config :farm_node, event_dispatcher: new_config
  end
end
