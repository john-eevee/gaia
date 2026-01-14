defmodule Gaia.Build.Mix do
  @moduledoc """
  Common mix configuration for Gaia projects.
  Includes common dependencies and settings.

  ## Usage:

  defmodule YourApp.MixProject do
    use Mix.Project
    Code.require_file("../build_common/common.exs", __DIR__)

    def project do
      [
        app: :your_app,
        version: "0.1.0",
        deps: deps()
      ] |> Gaia.Build.Mix.apply()

    end

    def application do
      [
        extra_applications: [:logger]
      ]
    end

    defp deps do
      [
      # Add your project-specific dependencies here
      ]
    end
  end
  """
  def apply(opts) do
    app = Keyword.fetch!(opts, :app)
    version = Keyword.fetch!(opts, :version)
    deps = Keyword.get(opts, :deps, [])
    aliases = Keyword.get(opts, :aliases, [])
    compilers = Keyword.get(opts, :compilers, [])
    elixirc_paths = Keyword.get(opts, :elixirc_paths, [])

    combined = [
      app: app,
      version: version,
      elixir: elixir_version(),
      start_permanent: Mix.env() == :prod,
      deps: common_deps() ++ deps,
      aliases: common_aliases() ++ aliases,
      compilers: common_compilers() ++ compilers,
      elixirc_paths: elixirc_paths(Mix.env()) ++ elixirc_paths,
      dialyzer: [plt_add_apps: [:mix, :ex_unit, :eex]]
    ]

    Keyword.merge(opts, combined) |> IO.inspect(label: "Mix Project Configuration")
  end

  defp elixir_version, do: "~> 1.19"

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp common_compilers do
    Mix.compilers()
  end

  defp common_deps do
    [
      {:jason, "~> 1.4"},
      {:x509, "~> 0.9"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:usage_rules, "~> 0.1", only: [:dev, :test], runtime: false},
      {:testing_facility, path: "../testing_facility", only: [:test]}
    ]
  end

  defp common_aliases do
    [
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
