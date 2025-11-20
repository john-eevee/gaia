import Config

config :hub, Gaia.Hub.Repo,
  database: "hub_dev",
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  types: Gaia.Hub.EctoTypes,
  pool_size: 10,
  migration_primary_key: [type: :binary_id]

# Do not include metadata nor timestamps in development logs
config :logger, :default_formatter, format: "[$level] $message\n"
