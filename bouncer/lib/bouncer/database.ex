defmodule Gaia.Bouncer.Database do
  @moduledoc """
  Database connection pool and query interface for certificate status lookups.

  Uses Postgrex for PostgreSQL connectivity with a dedicated read-only user.
  """

  use GenServer
  require Logger

  @doc """
  Starts the database connection pool.
  """
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Checks the certificate status in the database.

  Returns:
  - `{:ok, :valid}` if the certificate is valid
  - `{:ok, :revoked}` if the certificate is revoked
  - `{:ok, :unknown}` if the certificate is not found
  - `{:error, reason}` on database errors
  """
  @spec check_certificate_status(String.t()) ::
          {:ok, :valid | :revoked | :unknown} | {:error, term()}
  def check_certificate_status(serial) when is_binary(serial) do
    GenServer.call(__MODULE__, {:check_status, serial})
  end

  ## GenServer Callbacks

  @impl true
  def init(_) do
    db_config = Application.get_env(:bouncer, :database, [])

    case Postgrex.start_link(db_config) do
      {:ok, conn} ->
        Logger.info("Database connection established")
        {:ok, %{conn: conn}}

      {:error, reason} ->
        Logger.error("Failed to connect to database: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:check_status, serial}, _from, %{conn: conn} = state) do
    query = """
    SELECT status
    FROM certificate_status
    WHERE certificate_serial = $1
    LIMIT 1
    """

    result =
      case Postgrex.query(conn, query, [serial]) do
        {:ok, %Postgrex.Result{rows: [[status]]}} ->
          {:ok, normalize_status(status)}

        {:ok, %Postgrex.Result{rows: []}} ->
          {:ok, :unknown}

        {:error, reason} ->
          Logger.error("Database query failed: #{inspect(reason)}")
          {:error, reason}
      end

    {:reply, result, state}
  end

  # Normalize status boolean to atoms
  # true (1) = valid, false (0) = revoked
  defp normalize_status(true), do: :valid
  defp normalize_status(false), do: :revoked
  defp normalize_status(_), do: :unknown
end
