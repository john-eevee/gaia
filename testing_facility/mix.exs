defmodule TestingFacility.MixProject do
  use Mix.Project

  def project do
    [
      app: :testing_facility,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:x509, "~> 0.9"}
    ]
  end
end
