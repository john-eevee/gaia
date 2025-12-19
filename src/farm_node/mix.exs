defmodule Gaia.FarmNode.MixProject do
  use Mix.Project
  Code.require_file("../build/mix.exs", __DIR__)

  def project do
    [
      app: :farm_node,
      version: "0.1.0",
      deps: deps()
    ]
    |> Gaia.Build.Mix.apply()
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Gaia.FarmNode.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:req, "~> 0.5"}
    ]
  end
end
