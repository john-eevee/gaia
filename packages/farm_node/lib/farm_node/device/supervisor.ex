defmodule Gaia.FarmNode.Device.Supervisor do
  @moduledoc "Dynamic supervisor for simulated devices."
  use DynamicSupervisor

  def start_link(_args) do
    DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @impl true
  def init(:ok) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  def start_device(opts) when is_list(opts) do
    # Allow callers to specify an explicit module for the device (useful for
    # tests and custom device modules). Fallback to the legacy module name
    # if none provided.
    module = Keyword.get(opts, :module, Gaia.FarmNode.Device)

    child_spec = %{
      id: opts[:id],
      start: {module, :start_link, [opts]},
      restart: :transient
    }

    DynamicSupervisor.start_child(__MODULE__, child_spec)
  end
end
