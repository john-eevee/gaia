# This file is responsible for configuring your application
# and its dependencies with the help of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.
import Config

# Sample configuration:
#
#     config :logger, :console,
#       level: :info,
#       format: "$date $time [$level] $metadata$message\n",
#       metadata: [:user_id]
#

config :hub,
  cacert: [
    cert: "priv/cert/selfsigned.pem",
    key: "priv/cert/selfsigned_key.pem"
  ]

config :hub,
  ecto_repos: [Gaia.Hub.Repo]

import_config "#{config_env()}.exs"
