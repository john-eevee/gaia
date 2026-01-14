import Config

config :farm_node,
  # The Hub base URL is required for the Farm Node to communicate with the central Hub.
  # This should be configured per environment or via environment variables in runtime.exs.
  hub_base_url: nil,
  ssl_dir: "priv/ssl",
  http_client: Req,
  event_dispatcher: [
    buffer_size: 10,
    flush_interval: 5000,
    subscriptions: ["telemetry:all", "event:all"]
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
