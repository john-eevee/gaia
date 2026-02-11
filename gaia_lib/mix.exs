defmodule GaiaLib.MixProject do
  Code.require_file("../.common.exs")
  alias Gaia.Common.DepsCatalog
  use Mix.Project

  def project do
    [
      app: :gaia_lib,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      tags: [
        scope: :shared
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :public_key]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      DepsCatalog.get_dep(:credo),
      DepsCatalog.get_dep(:x509)
    ]
  end

  defp aliases() do
    [
      setup: ["deps.get"],
      "test.integration": ["test --only integration"]
    ]
  end
end
