defmodule Gaia.Hub.MixProject do
  use Mix.Project
  Code.require_file("../build/mix.exs", __DIR__)

  def project do
    [
      app: :hub,
      version: "0.1.0",
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
    |> Gaia.Build.Mix.apply()
  end

  def cli do
    [preferred_envs: [ci: :test]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Gaia.Hub.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ecto_sql, "~> 3.13"},
      {:postgrex, ">= 0.0.0"},
      {:geo_postgis, "~> 3.7"},
      {:argon2_elixir, "~> 4.0"}
    ]
  end

  defp aliases() do
    [
      "gen.cert": "x509.gen.selfsigned",
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.setup --quiet", "test"]
    ]
  end
end
