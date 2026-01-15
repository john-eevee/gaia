defmodule Gaia.FarmNode.MixProject do
  use Mix.Project
  Code.require_file("../build_common/mix.exs", __DIR__)

  def project do
    [
      app: :farm_node,
      version: "0.1.0",
      deps: deps(),
      releases: releases(),
      test_coverage: [
        ignore_modules: [
          ~r/Mix.Tasks.FarmNode.*/,
          Gaia.FarmNode.HubConnection.Provisioning.CLI
        ]
      ]
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
      {:req, "~> 0.5"},
      {:ecto, "~> 3.13"},
      {:mox, "~> 1.0", only: :test}
    ]
  end

  defp releases do
    [
      farm_node: [
        include_executables_for: [:unix],
        applications: [runtime_tools: :permanent],
        steps: [:assemble, &copy_provision_script/1, :tar]
      ]
    ]
  end

  # Copy the provision script to the release bin directory
  defp copy_provision_script(release) do
    # Source is relative to the project root
    project_root = File.cwd!()
    source = Path.join([project_root, "rel", "commands", "provision.sh"])
    target = Path.join([release.path, "bin", "provision"])

    File.mkdir_p!(Path.dirname(target))
    File.cp!(source, target)
    File.chmod!(target, 0o755)

    IO.puts("* copied provision script to #{Path.relative_to_cwd(target)}")
    release
  end
end
