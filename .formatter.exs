# Formatter configuration for all Gaia projects.
# This file will be used by Mix tasks such as `mix format` when run from the root of the project.

# Nonetheless, each application can have its `.formatter.exs` file, which will be
# used when running `mix format` from inside that application, or from the root.

# This file only specifies to format the relevant subdirectories inside `src/`,
# and none outside of it.

[
  subdirectories: ["{mix,.formatter}.exs", "src/**/{config,lib,test}/**/*.{ex,exs}"]
]
