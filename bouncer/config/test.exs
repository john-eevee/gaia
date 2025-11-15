import Config

# Test configuration
config :logger, level: :warning

# Test database configuration
config :bouncer, :database,
  hostname: "localhost",
  port: 5432,
  database: "bouncer_test",
  username: "postgres",
  password: "postgres",
  pool_size: 5

# Test server configuration
config :bouncer, port: 4445
