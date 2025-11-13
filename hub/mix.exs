defmodule Gaia.Hub.MixProject do
  use Mix.Project

  def project do
    [
      app: :hub,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  def cli do
    [preferred_envs: [ci: :test]]
  end

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
      {:x509, "~> 0.9"},
      {:argon2_elixir, "~> 4.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases() do
    [
      "gen.cert": "x509.gen.selfsigned",
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
