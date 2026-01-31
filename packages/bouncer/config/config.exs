import Config

# Bouncer server configuration
config :bouncer,
  port: System.get_env("BOUNCER_PORT", "4444") |> String.to_integer()

# Database configuration
config :bouncer, :database,
  hostname: System.get_env("DB_HOST", "localhost"),
  port: System.get_env("DB_PORT", "5432") |> String.to_integer(),
  database: System.get_env("DB_NAME", "gaia"),
  username: System.get_env("DB_USER", "bouncer_ro"),
  password: System.get_env("DB_PASSWORD", ""),
  pool_size: String.to_integer(System.get_env("DB_POOL_SIZE", "10"))

# Logger configuration
config :logger, :default_formatter, metadata: [:request_id, :duration_ms, :status]

# Import environment specific config
import_config "#{config_env()}.exs"
