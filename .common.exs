defmodule Gaia.Common do
  def version do
    case System.get_env("VERSION") do
      nil -> "./VERSION" |> File.read!() |> String.trim()
      version -> version
    end
    |> Version.parse!()
    |> Version.to_string()
  end

  def elixir_version do
    case System.get_env("ELIXIR_VERSION") do
      nil -> "1.19.5"
      version -> version
    end
    |> Version.parse!()
    |> Version.to_string()
    |> then(&"~> #{&1}")
  end

  defmodule DepsCatalog do

    def get_dep(name) when is_atom(name) do
      deps()
      |> Enum.find(fn dep_manifest -> elem(dep_manifest, 0) == name end)
    end

    defp deps do
      [
        {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
      ]
    end
  end
end
