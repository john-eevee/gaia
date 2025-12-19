defmodule Gaia.Device do
  @moduledoc """
  Convenience macro to define device modules.

  Use example:

    defmodule MyDevices.TempSensor do
      use Gaia.Device, type: :temperature_sensor
    end

  The generated module will provide `start_link/1` which accepts `:id` and
  other options forwarded to `Gaia.FarmNode.Device`.
  """

  defmacro __using__(opts) do
    type = Keyword.fetch!(opts, :type)

    quote bind_quoted: [type: type] do
      def start_link(opts) when is_list(opts) do
        opts = Keyword.put_new(opts, :type, unquote(type))
        Gaia.FarmNode.Device.Supervisor.start_device(opts)
      end

      def child_spec(opts) do
        %{
          id: opts[:id] || make_ref(),
          start: {Gaia.FarmNode.Device, :start_link, [opts]},
          restart: :transient
        }
      end

      defoverridable child_spec: 1
    end
  end
end
