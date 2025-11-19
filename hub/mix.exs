defmodule Gaia.Hub.MixProject do
  use Mix.Project

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
      {:jason, "~> 1.2"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, ">= 0.0.0"},
      {:geo_postgis, "~> 3.7"},
      {:x509, "~> 0.9"},
      {:argon2_elixir, "~> 4.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:testing_facility, path: "../testing_facility", only: [:test]}
    ]
  end

  defp aliases() do
    [
      "gen.cert": "x509.gen.selfsigned",
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.setup --quiet", "test"],
      ci: [
        "deps.get",
        "compile --warning-as-errors",
        "test --cover",
        "credo",
        "format --check-formatted",
        "deps.audit"
      ]
    ]
  end
end
