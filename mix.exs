defmodule Gaia.MixWorkspace do
  Code.require_file(".common.exs", __DIR__)
  alias Gaia.Common.DepsCatalog
  use Mix.Project

  def project do
    [
      app: :gaia,
      version: Gaia.Common.version(),
      elixir: Gaia.Common.elixir_version(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: [],
      workspace: [
        type: :workspace
      ],
      lockfile: "workspace.lock"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: []
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      DepsCatalog.get_dep(:credo),
      {:workspace, "~> 0.3"}
    ]
  end
end
