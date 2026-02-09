defmodule GaiaFarm.MixProject do
  Code.require_file("../.common.exs")
  alias Gaia.Common.DepsCatalog
  use Mix.Project

  def project do
    [
      app: :gaia_farm,
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
      mod: {GaiaFarm.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      DepsCatalog.get_dep(:credo)
    ]
  end

  defp aliases do
    [
      setup: ["deps.get"]
    ]
  end
end
