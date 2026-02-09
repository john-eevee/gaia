defmodule GaiaHub.MixProject do
  Code.require_file("../.common.exs")
  use Mix.Project
  alias Gaia.Common.DepsCatalog

  def project do
    [
      app: :gaia_hub,
      version: Gaia.Common.version(),
      elixir: Gaia.Common.elixir_version(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      tags: [
        scope: :app
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {GaiaHub.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      DepsCatalog.get_dep(:credo)
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get"]
    ]
  end
end
