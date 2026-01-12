defmodule Gaia.FarmNode.HubConnection.Heartbeat do
  use GenServer

  defmodule State do
    @moduledoc false
    defstruct [:interval, :timeout, :timer_ref]
  end

  alias __MODULE__.State

  @typep milliseconds :: non_neg_integer()

  @type opts() :: [
          name: atom() | __MODULE__,
          interval: milliseconds(),
          timeout: milliseconds()
        ]

  @doc """
  Starts the Heartbeart server with the following options:

  - name: the registered server name, defaults to this module´s name
  - interval: the interval in milliseconds each heartbeat will be triggered, defaults to 5 minutes
  - timeout: the timeout in milliseconds to receive a response from the heartbeat call, defaults to 30 seconds
  """
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    interval = Keyword.get(opts, :interval, :timer.minutes(5))
    timeout = Keyword.get(opts, :timeout, :timer.seconds(30))
    GenServer.start_link(__MODULE__, [interval: interval, timeout: timeout], name: name)
  end

  @doc false
  @impl GenServer
  def init(opts) do
    {:ok, %State{interval: opts[:interval], timeout: opts[:timeout]},
     {:continue, :schedule_heartbeat}}
  end

  @impl GenServer
  def handle_continue(:schedule_heartbeat, %State{} = state) do
    ref = schedule_heartbeat(state.interval)
    new_state = %State{state | timer_ref: ref}
    {:noreply, new_state}
  end

  @impl GenServer
  def handle_info(:beat, %State{} = state) do
    # call hub api
    # if failts, send a message to the provision cleaning server

    ref = schedule_heartbeat(state.interval)
    new_state = %State{state | timer_ref: ref}
    {:noreply, new_state}
  end

  defp schedule_heartbeat(interval) do
    Process.send_after(self(), :beat, interval)
  end
end
