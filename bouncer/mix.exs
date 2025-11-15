defmodule Gaia.Bouncer.MixProject do
  use Mix.Project

  def project do
    [
      app: :bouncer,
      version: "0.1.0",
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases()
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
      mod: {Gaia.Bouncer.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:bandit, "~> 1.0"},
      {:plug, "~> 1.15"},
      {:postgrex, "~> 0.17"},
      {:telemetry, "~> 1.2"},
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:jason, "~> 1.4"},
      {:x509, "~> 0.8"},
      {:mox, "~> 1.0", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases() do
    [
      ci: [
        "deps.get",
        "compile --warnings-as-errors",
        "test --cover",
        "credo",
        "format --check-formatted",
        "deps.audit"
      ]
    ]
  end

  defp releases do
    [
      bouncer: [
        include_executables_for: [:unix],
        applications: [runtime_tools: :permanent]
      ]
    ]
  end
end
