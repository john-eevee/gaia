defmodule Gaia.FarmNode.Config do
  @moduledoc """
  Unified configuration management for the Gaia Farm Node.

  This module centralizes all application configurations, providing a single source
  of truth and enforcing strict validation at startup. By validating configurations
  early, we ensure the node operates within expected parameters and provides clear,
  actionable feedback if misconfigured.

  ## Usage

  Access configurations via the provided getter functions:

      Gaia.FarmNode.Config.hub_base_url()
      Gaia.FarmNode.Config.ssl_dir()

  ## Validation

  Configurations should be validated during the application startup sequence in
  `Gaia.FarmNode.Application.start/2`:

      defmodule Gaia.FarmNode.Application do
        use Application

        def start(_type, _args) do
          Gaia.FarmNode.Config.validate!()
          # ...
        end
      end

  ## Configuration Keys

  The following keys under the `:farm_node` application are managed by this module:

  * `:hub_base_url` (Required) - The base URL of the Hub (e.g., "https://hub.example.com").
  * `:ssl_dir` (Default: "priv/ssl") - Directory where mTLS certificates are stored.
  * `:http_client` (Default: `Req`) - The HTTP client module used for Hub communication.
  * `:event_dispatcher` - Keyword list for event batching:
    * `:buffer_size` (Default: 10)
    * `:flush_interval` (Default: 5000)
    * `:subscriptions` (Default: ["telemetry:all", "event:all"])

  ## Examples

  ### Configuring via runtime.exs

  In `config/runtime.exs`:

      import Config

      config :farm_node,
        hub_base_url: System.get_env("HUB_URL") || "https://hub.project-gaia.io",
        ssl_dir: System.get_env("SSL_DIR") || "priv/ssl",
        event_dispatcher: [
          buffer_size: 50,
          flush_interval: 10_000
        ]

  ### Accessing configuration in code

      # Get specific values
      url = Gaia.FarmNode.Config.hub_base_url()
      client = Gaia.FarmNode.Config.http_client()

      # Access nested event dispatcher settings
      opts = Gaia.FarmNode.Config.event_dispatcher()
      buffer_size = opts[:buffer_size]

  ### Unified access

  You can retrieve the entire configuration state as a map:

      config_map = Gaia.FarmNode.Config.current()
      # %{hub_base_url: "...", ssl_dir: "...", ...}
  """

  defmodule HubBaseUrlError do
    @moduledoc "Exception raised when :hub_base_url is missing or invalid."
    defexception [:message, :value, :instruction]

    @impl true
    def exception(opts) do
      value = opts[:value]
      instruction = opts[:instruction]

      message = """
      Invalid Hub Configuration!
      Key: :hub_base_url
      Current Value: #{inspect(value)}

      Problem:
      #{instruction}

      Fix: Define `config :farm_node, hub_base_url: "https://..."` in your config files.
      """

      %__MODULE__{message: message, value: value, instruction: instruction}
    end
  end

  defmodule SslDirError do
    @moduledoc "Exception raised when :ssl_dir is invalid."
    defexception [:message, :value, :instruction]

    @impl true
    def exception(opts) do
      value = opts[:value]
      instruction = opts[:instruction]

      message = """
      Invalid SSL Directory Configuration!
      Key: :ssl_dir
      Current Value: #{inspect(value)}

      Problem:
      #{instruction}

      Fix: Ensure :ssl_dir is a valid string path in your configuration.
      """

      %__MODULE__{message: message, value: value, instruction: instruction}
    end
  end

  defmodule HttpClientError do
    @moduledoc "Exception raised when :http_client is invalid."
    defexception [:message, :value, :instruction]

    @impl true
    def exception(opts) do
      value = opts[:value]
      instruction = opts[:instruction]

      message = """
      Invalid HTTP Client Configuration!
      Key: :http_client
      Current Value: #{inspect(value)}

      Problem:
      #{instruction}

      Fix: Set :http_client to a valid module atom (e.g., Req).
      """

      %__MODULE__{message: message, value: value, instruction: instruction}
    end
  end

  defmodule EventDispatcherError do
    @moduledoc "Exception raised when :event_dispatcher settings are invalid."
    defexception [:message, :key, :value, :instruction]

    @impl true
    def exception(opts) do
      key = opts[:key]
      value = opts[:value]
      instruction = opts[:instruction]

      message = """
      Invalid Event Dispatcher Configuration!
      Key: #{inspect(key)}
      Current Value: #{inspect(value)}

      Problem:
      #{instruction}

      Fix: Update the :event_dispatcher keyword list in your configuration.
      """

      %__MODULE__{message: message, key: key, value: value, instruction: instruction}
    end
  end

  @default_ssl_dir "priv/ssl"
  @default_buffer_size 10
  @default_flush_interval 5_000
  @default_subscriptions ["telemetry:all", "event:all"]

  @doc """
  Validates all required and optional configurations.

  This function should be called early in the application boot process.
  It checks for the presence of required keys and data type correctness for all keys.

  Raises specialized exceptions if any configuration is invalid.
  """
  @spec validate!() :: :ok
  def validate! do
    validate_hub_base_url!()
    validate_ssl_dir!()
    validate_http_client!()
    validate_event_dispatcher!()
    :ok
  end

  @doc """
  Returns the Hub base URL.
  """
  @spec hub_base_url() :: String.t() | nil
  def hub_base_url do
    Application.get_env(:farm_node, :hub_base_url)
  end

  @doc """
  Returns the directory for SSL certificates.
  """
  @spec ssl_dir() :: String.t()
  def ssl_dir do
    Application.get_env(:farm_node, :ssl_dir, @default_ssl_dir)
  end

  @doc """
  Returns the HTTP client module.
  """
  @spec http_client() :: module()
  def http_client do
    Application.get_env(:farm_node, :http_client, Req)
  end

  @doc """
  Returns the configuration for the event dispatcher as a keyword list.
  """
  @spec event_dispatcher() :: [
          buffer_size: integer(),
          flush_interval: integer(),
          subscriptions: [String.t()]
        ]
  def event_dispatcher do
    config = Application.get_env(:farm_node, :event_dispatcher, [])

    [
      buffer_size: Keyword.get(config, :buffer_size, @default_buffer_size),
      flush_interval: Keyword.get(config, :flush_interval, @default_flush_interval),
      subscriptions: Keyword.get(config, :subscriptions, @default_subscriptions)
    ]
  end

  @doc """
  Returns the entire configuration as a map for unified access.
  """
  @spec current() :: map()
  def current do
    %{
      hub_base_url: hub_base_url(),
      ssl_dir: ssl_dir(),
      http_client: http_client(),
      event_dispatcher: event_dispatcher()
    }
  end

  # --- Internal Validations ---

  defp validate_hub_base_url! do
    url = hub_base_url()

    cond do
      is_nil(url) ->
        raise HubBaseUrlError,
          value: url,
          instruction: "The :hub_base_url is missing. This is required for Hub communication."

      not is_binary(url) ->
        raise HubBaseUrlError,
          value: url,
          instruction: "The :hub_base_url must be a string."

      true ->
        uri = URI.parse(url)

        if not (uri.host && uri.scheme in ["http", "https"]) do
          raise HubBaseUrlError,
            value: url,
            instruction: "The :hub_base_url must be a valid absolute URL (http/https)."
        end
    end
  end

  defp validate_ssl_dir! do
    dir = ssl_dir()

    if String.length(dir) == 0 do
      raise SslDirError,
        value: dir,
        instruction: "The :ssl_dir must be a string representing a directory path."
    end
  end

  defp validate_http_client! do
    client = http_client()

    if not is_atom(client) do
      raise HttpClientError,
        value: client,
        instruction: "The :http_client must be a module atom (e.g., Req)."
    end
  end

  defp validate_event_dispatcher! do
    config = Application.get_env(:farm_node, :event_dispatcher, [])

    if not is_list(config) do
      raise EventDispatcherError,
        key: :event_dispatcher,
        value: config,
        instruction: "The :event_dispatcher configuration must be a keyword list."
    end

    buffer_size = Keyword.get(config, :buffer_size, @default_buffer_size)

    if not is_integer(buffer_size) and buffer_size > 0 do
      raise EventDispatcherError,
        key: [:event_dispatcher, :buffer_size],
        value: buffer_size,
        instruction: "The :buffer_size must be a positive integer."
    end

    flush_interval = Keyword.get(config, :flush_interval, @default_flush_interval)

    if not is_integer(flush_interval) and flush_interval > 0 do
      raise EventDispatcherError,
        key: [:event_dispatcher, :flush_interval],
        value: flush_interval,
        instruction: "The :flush_interval must be a positive integer (milliseconds)."
    end

    subscriptions = Keyword.get(config, :subscriptions, @default_subscriptions)

    if not is_list(subscriptions) and Enum.all?(subscriptions, &is_binary/1) do
      raise EventDispatcherError,
        key: [:event_dispatcher, :subscriptions],
        value: subscriptions,
        instruction: "The :subscriptions must be a list of strings (topics)."
    end
  end
end
