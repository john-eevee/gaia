# Gaia Feature Framework (GFF)

A mental model and guardrails for building features in the Gaia codebase.

---

## The Core Loop: CIDER

Every feature follows this cycle:

```
    ┌─────────────────────────────────────────────────────┐
    │                                                     │
    ▼                                                     │
┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
│Context │───▶│Interface│───▶│ Domain │───▶│ Effect │───▶│ React  │
│  Find  │    │ Define │    │  Build │    │Execute │    │  Emit  │
└────────┘    └────────┘    └────────┘    └────────┘    └────────┘
```

**C**ontext → **I**nterface → **D**omain → **E**ffect → **R**eact

### 1. Context (Where does this belong?)

Ask: *Which bounded context owns this feature?*

```
Hub Contexts:
├── CoopIdentity      → Farms, Farmers, Provisioning, Certificates
├── RegionalAnalytics → Aggregated insights, Benchmarks, Trends
├── SharedResources   → Equipment, Labor, Infrastructure sharing
├── Marketplace       → Collective offers, Pricing, Supply chain
└── GroupProcurement  → Bulk purchasing, Supplier coordination

FarmNode Contexts:
├── FarmOperations    → Fields, Crops, Tasks, Yields
├── DeviceManagement  → Sensors, Actuators, Telemetry
├── LocalRules        → Automation rules, Alerts, Actions
└── HubConnection     → Provisioning, Heartbeat, Data sync

Bouncer:
└── (Single purpose)  → Certificate validation only
```

**Rule**: If you can't place it, you're either missing a context or building something that spans contexts (use events).

### 2. Interface (What's the contract?)

Define the public API first. This is your *use case*.

```elixir
# lib/hub/coop_identity.ex (Context Facade)

@doc """
Registers a new farm in the cooperative.

Returns the farm with a single-use provisioning key for node setup.
"""
@spec register_farm(attrs :: map()) :: 
  {:ok, Farm.t()} | {:error, Ecto.Changeset.t()}
def register_farm(attrs) do
  # Implementation hidden from callers
end
```

**Rules**:
- One module per context (the "facade")
- Each public function = one use case
- Always `{:ok, result} | {:error, reason}`
- Always `@doc` and `@spec`
- No temporal coupling (caller shouldn't need to call A before B)

### 3. Domain (What are the business rules?)

Build the internals: schemas, validations, business logic.

```
lib/hub/coop_identity/
├── farm.ex                    # Ecto Schema + changeset
├── farmer.ex                  # Ecto Schema + changeset  
├── data_sharing_policy.ex     # Ecto Schema + policy logic
├── initial_provisioning_key.ex # Schema + generation logic
└── services/                  # Complex operations (optional)
    └── farm_onboarding.ex     # Multi-step orchestration
```

**Rules**:
- Schemas validate their own data via changesets
- Business logic lives in the schema module or dedicated service modules
- No database calls in schemas (that's the facade's job)
- Pattern match, don't nil-check

### 4. Effect (What external things happen?)

Side effects: database writes, HTTP calls, file I/O.

```elixir
# In the context facade
def register_farm(attrs) do
  Multi.new()
  |> Multi.insert(:farm, Farm.changeset(%Farm{}, attrs))
  |> Multi.insert(:policy, fn %{farm: farm} ->
    DataSharingPolicy.default_changeset(farm)
  end)
  |> Multi.insert(:key, fn %{farm: farm} ->
    InitialProvisioningKey.generate_changeset(farm)
  end)
  |> Repo.transaction()
  |> case do
    {:ok, %{farm: farm}} -> {:ok, Repo.preload(farm, [:provisioning_key])}
    {:error, _step, changeset, _} -> {:error, changeset}
  end
end
```

**Rules**:
- Use `Ecto.Multi` for multi-step database operations
- Use `with` for chaining fallible operations
- Wrap external calls in behaviours (for testing)
- Effects happen in the facade, not in schemas

### 5. React (What events propagate?)

Cross-context communication via events over the **event bus**.

#### The Event Bus

Phoenix.PubSub is the event bus. Each application starts it in its supervision tree:

```elixir
# lib/hub/application.ex
children = [
  {Phoenix.PubSub, name: Gaia.Hub.PubSub},
  # ...
]
```

#### Publishing Events

```elixir
# After successful registration
defp broadcast_farm_created(farm) do
  event = %FarmCreated{id: farm.id, name: farm.name}
  Phoenix.PubSub.broadcast(
    Gaia.Hub.PubSub,
    Gaia.Event.topic(event),
    Gaia.Event.payload(event)
  )
end
```

#### Subscribing to Events

Subscribers are GenServers (or any process) that subscribe on init:

```elixir
# lib/hub/regional_analytics/farm_listener.ex
defmodule Gaia.Hub.RegionalAnalytics.FarmListener do
  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    Phoenix.PubSub.subscribe(Gaia.Hub.PubSub, "coop_identity:farms")
    {:ok, %{}}
  end

  @impl true
  def handle_info({:farm_created, %{id: id, name: name}}, state) do
    # React to event - initialize analytics for new farm
    {:noreply, state}
  end
end
```

#### Event Struct Pattern

```elixir
# lib/hub/coop_identity/events/farm_created.ex
defmodule Gaia.Hub.CoopIdentity.Events.FarmCreated do
  @moduledoc "Emitted when a new farm joins the cooperative."
  
  use Gaia.Event
  
  defstruct [:id, :name, :created_at]
  
  @type t :: %__MODULE__{
    id: Ecto.UUID.t(),
    name: String.t(),
    created_at: DateTime.t()
  }
end
```

#### The Gaia.Event Protocol

```elixir
# lib/shared/event.ex (in a shared library or each app)
defprotocol Gaia.Event do
  @doc "Returns the topic string for this event"
  @spec topic(t) :: String.t()
  def topic(event)
  
  @doc "Returns the payload tuple for this event"
  @spec payload(t) :: {atom(), map()}
  def payload(event)
end

# Usage macro for event structs
defmodule Gaia.Event.Macros do
  defmacro __using__(_opts) do
    quote do
      defimpl Gaia.Event do
        def topic(%{__struct__: module}) do
          module
          |> Module.split()
          |> Enum.take(3)  # e.g., ["Gaia", "Hub", "CoopIdentity"]
          |> Enum.drop(1)  # ["Hub", "CoopIdentity"]
          |> Enum.map(&Macro.underscore/1)
          |> Enum.join(":")  # "hub:coop_identity"
        end
        
        def payload(%{__struct__: module} = event) do
          event_name = 
            module
            |> Module.split()
            |> List.last()
            |> Macro.underscore()
            |> String.to_atom()
          
          {event_name, Map.from_struct(event)}
        end
      end
    end
  end
end
```

#### Event Flow

```
┌─────────────────┐     broadcast      ┌─────────────────┐
│  CoopIdentity   │ ─────────────────▶ │  Phoenix.PubSub │
│  (publisher)    │   topic: "hub:     │     (bus)       │
└─────────────────┘   coop_identity"   └────────┬────────┘
                                                │
                      subscribe                 │
              ┌─────────────────────────────────┼─────────────────┐
              │                                 │                 │
              ▼                                 ▼                 ▼
┌─────────────────┐               ┌─────────────────┐   ┌─────────────────┐
│RegionalAnalytics│               │ SharedResources │   │   Marketplace   │
│  FarmListener   │               │   FarmListener  │   │  FarmListener   │
└─────────────────┘               └─────────────────┘   └─────────────────┘
```

**Rules**:
- Events are structs implementing `Gaia.Event`
- Events are facts (past tense: `FarmCreated`, not `CreateFarm`)
- Never call another context directly—emit an event
- Subscribers handle events idempotently
- Each subscriber is a supervised GenServer
- Failed handlers crash and restart (don't break the publisher)

---

## The Anatomy of a Feature

### File Structure Template

```
lib/<app>/<context>.ex                    # Facade (public API)
lib/<app>/<context>/
├── error.ex                              # Context error struct
├── <entity>.ex                           # Ecto Schema
├── <value_object>.ex                     # Non-persisted struct
├── <service>.ex                          # Complex operation
├── <name>_listener.ex                    # Event subscriber (GenServer)
└── events/
    └── <entity>_<action>.ex              # Event struct

test/<app>/<context>_test.exs             # Facade tests
test/<app>/<context>/
├── <entity>_test.exs                     # Schema/unit tests
└── <service>_test.exs                    # Service tests

test/support/fixtures/<context>/
└── <entity>.ex                           # Test fixtures
```

### Naming Conventions

| Type | Pattern | Example |
|------|---------|---------|
| Context module | `Gaia.<App>.<Context>` | `Gaia.Hub.CoopIdentity` |
| Entity | `Gaia.<App>.<Context>.<Entity>` | `Gaia.Hub.CoopIdentity.Farm` |
| Error | `Gaia.<App>.<Context>.Error` | `Gaia.Hub.CoopIdentity.Error` |
| Event | `Gaia.<App>.<Context>.Events.<Event>` | `Gaia.Hub.CoopIdentity.Events.FarmCreated` |
| Listener | `Gaia.<App>.<Context>.<Name>Listener` | `Gaia.Hub.RegionalAnalytics.FarmListener` |
| Service | `Gaia.<App>.<Context>.<Action>` | `Gaia.Hub.Provision.Signing` |
| Behaviour | `Gaia.<App>.<Context>.<Name>` | `Gaia.Bouncer.Database` |
| Implementation | `Gaia.<App>.<Context>.<Tech><Name>` | `Gaia.Bouncer.PostgrexDatabase` |

---

## Decision Trees

### "Where does this code go?"

```
Is it a public operation a user/system would invoke?
├── Yes → Context Facade (lib/<app>/<context>.ex)
└── No
    ├── Is it data structure + validation?
    │   └── Yes → Schema (lib/<app>/<context>/<entity>.ex)
    ├── Is it a multi-step orchestration?
    │   └── Yes → Service module (lib/<app>/<context>/<service>.ex)
    ├── Is it a cross-context notification?
    │   └── Yes → Event struct (lib/<app>/<context>/events/<event>.ex)
    └── Is it an external dependency?
        └── Yes → Behaviour + Implementation
```

### "How do I handle this dependency?"

```
Is it an external service (HTTP, DB, file system)?
├── Yes
│   ├── Define a behaviour (callback module)
│   ├── Create implementation module
│   ├── Inject via Application config
│   └── Mock with Mox in tests
└── No (internal module)
    └── Just call it directly
```

```elixir
# Pattern: Behaviour-based injection

# 1. Define behaviour
defmodule Gaia.FarmNode.HubConnection.Client do
  @callback post(url :: String.t(), body :: map()) :: 
    {:ok, map()} | {:error, term()}
end

# 2. Implementation
defmodule Gaia.FarmNode.HubConnection.ReqClient do
  @behaviour Gaia.FarmNode.HubConnection.Client
  
  @impl true
  def post(url, body), do: Req.post(url, json: body)
end

# 3. Config-based selection
# config/config.exs
config :farm_node, :hub_client, Gaia.FarmNode.HubConnection.ReqClient

# config/test.exs  
config :farm_node, :hub_client, Gaia.FarmNode.HubConnection.ClientMock

# 4. Runtime lookup
defp client, do: Application.get_env(:farm_node, :hub_client)
```

### "Should this be a GenServer?"

```
Does it need to:
├── Hold state across calls? → Yes, GenServer
├── React to messages over time? → Yes, GenServer
├── Represent a physical device? → Yes, GenServer (via Device macro)
├── Run periodic tasks? → Yes, GenServer with handle_info/Process.send_after
└── None of the above → No, just a module with functions
```

---

## Error Handling

### The Error Contract

Every context defines its own error struct. Public functions return:

```elixir
{:ok, result} | {:error, Context.Error.t()} | {:error, Ecto.Changeset.t()}
```

**Two error types are valid**:
1. **Domain errors** - Business logic failures, wrapped in context-specific error struct
2. **Validation errors** - Ecto changesets (kept as-is for field-level detail)

### Context Error Structure

Each context has an `error.ex` module:

```
lib/<app>/<context>/
├── error.ex                    # Context error definition
├── <entity>.ex
└── ...
```

### Error Definition Pattern

```elixir
# lib/hub/coop_identity/error.ex
defmodule Gaia.Hub.CoopIdentity.Error do
  @moduledoc """
  Error type for the CoopIdentity context.
  """

  @type reason ::
          :farm_not_found
          | :farmer_not_found
          | :key_expired
          | :key_already_used
          | :certificate_revoked
          | :unauthorized

  @type t :: %__MODULE__{
          reason: reason(),
          message: String.t(),
          context: map(),
          cause: Exception.t() | nil
        }

  defexception [:reason, :message, :context, :cause]

  @impl true
  def message(%__MODULE__{message: message}), do: message

  # Constructor functions for each error reason
  @spec farm_not_found(Ecto.UUID.t()) :: t()
  def farm_not_found(farm_id) do
    %__MODULE__{
      reason: :farm_not_found,
      message: "Farm not found: #{farm_id}",
      context: %{farm_id: farm_id},
      cause: nil
    }
  end

  @spec key_expired(String.t()) :: t()
  def key_expired(key_id) do
    %__MODULE__{
      reason: :key_expired,
      message: "Provisioning key has expired",
      context: %{key_id: key_id},
      cause: nil
    }
  end

  # Wrap external errors
  @spec wrap(reason(), String.t(), Exception.t()) :: t()
  def wrap(reason, message, cause) do
    %__MODULE__{
      reason: reason,
      message: message,
      context: %{},
      cause: cause
    }
  end
end
```

### Usage in Context Facade

```elixir
# lib/hub/coop_identity.ex
defmodule Gaia.Hub.CoopIdentity do
  alias __MODULE__.Error

  @spec get_farm(Ecto.UUID.t()) :: 
    {:ok, Farm.t()} | {:error, Error.t()}
  def get_farm(farm_id) do
    case Repo.get(Farm, farm_id) do
      nil -> {:error, Error.farm_not_found(farm_id)}
      farm -> {:ok, farm}
    end
  end

  @spec register_farm(map()) :: 
    {:ok, Farm.t()} | {:error, Ecto.Changeset.t()}
  def register_farm(attrs) do
    %Farm{}
    |> Farm.changeset(attrs)
    |> Repo.insert()
  end

  @spec provision_node(String.t(), String.t()) ::
    {:ok, Certificate.t()} | {:error, Error.t()}
  def provision_node(key, csr) do
    with {:ok, key_record} <- validate_key(key),
         {:ok, cert} <- sign_csr(csr, key_record) do
      {:ok, cert}
    end
  end

  defp validate_key(key) do
    case Repo.get_by(ProvisioningKey, key_hash: hash(key)) do
      nil -> {:error, Error.key_not_found(key)}
      %{expires_at: exp} when exp < now -> {:error, Error.key_expired(key)}
      %{used_at: used} when not is_nil(used) -> {:error, Error.key_already_used(key)}
      key_record -> {:ok, key_record}
    end
  end
end
```

### Pattern Matching on Errors

```elixir
# Caller can pattern match on reason
case CoopIdentity.provision_node(key, csr) do
  {:ok, cert} -> 
    send_certificate(cert)
  
  {:error, %Error{reason: :key_expired}} -> 
    {:error, :forbidden, "Provisioning key has expired"}
  
  {:error, %Error{reason: :key_already_used}} -> 
    {:error, :conflict, "Key has already been used"}
  
  {:error, %Error{} = err} -> 
    Logger.error("Provisioning failed", error: err)
    {:error, :internal_server_error, "Provisioning failed"}
end

# Or match on the struct directly for catch-all
case CoopIdentity.get_farm(id) do
  {:ok, farm} -> farm
  {:error, %Error{}} -> nil
end
```

### Changeset vs Domain Error Decision

```
Is this a validation failure on user input?
├── Yes → Return {:error, Ecto.Changeset.t()}
│         (preserves field-level errors for forms/API)
└── No
    ├── Is it a business rule violation? → {:error, Context.Error.t()}
    ├── Is it a "not found" case? → {:error, Context.Error.t()}
    ├── Is it an external service failure? → {:error, Context.Error.t()} with cause
    └── Is it an authorization failure? → {:error, Context.Error.t()}
```

### API Layer Translation

```elixir
# In Phoenix controller or Plug
defp translate_error(%CoopIdentity.Error{reason: reason}) do
  case reason do
    :farm_not_found -> {404, "Farm not found"}
    :farmer_not_found -> {404, "Farmer not found"}
    :key_expired -> {410, "Provisioning key has expired"}
    :key_already_used -> {409, "Provisioning key already used"}
    :certificate_revoked -> {403, "Certificate has been revoked"}
    :unauthorized -> {401, "Unauthorized"}
    _ -> {500, "Internal error"}
  end
end

defp translate_error(%Ecto.Changeset{} = changeset) do
  errors = Ecto.Changeset.traverse_errors(changeset, &translate_field_error/1)
  {422, %{errors: errors}}
end
```

### Logging Errors

```elixir
# Errors carry enough context for structured logging
Logger.error("Operation failed",
  reason: err.reason,
  message: err.message,
  context: err.context,
  cause: Exception.format(:error, err.cause)
)
```

### Error Naming Convention

| Type | Pattern | Example |
|------|---------|---------|
| Error module | `Gaia.<App>.<Context>.Error` | `Gaia.Hub.CoopIdentity.Error` |
| Reason atoms | `:<entity>_<state>` | `:farm_not_found`, `:key_expired` |
| Constructor | `<reason>(args)` | `Error.farm_not_found(id)` |

### Adding to File Structure

```
lib/<app>/<context>/
├── error.ex                    # Context error struct  ← NEW
├── <entity>.ex
├── <value_object>.ex
├── <service>.ex
└── events/
    └── <entity>_<action>.ex
```

---

## The Seven Laws of Gaia

### 1. Law of Autonomy
> Farm Nodes operate independently. Hub is enhancement, not life support.

- Farm Node must work offline
- All Hub calls are async with timeouts
- Local data is authoritative for local operations

### 2. Law of Explicit Trust
> Data sharing is opt-in. Default is `share_nothing`.

```elixir
# ALWAYS check before aggregating
def aggregate_yields(farm_ids) do
  farm_ids
  |> Enum.filter(&DataSharingPolicy.allows?(&1, :yield_data))
  |> Enum.map(&fetch_yield/1)
end
```

### 3. Law of Boundaries
> Contexts never call each other directly. Events only.

```elixir
# WRONG
def register_farm(attrs) do
  farm = create_farm(attrs)
  RegionalAnalytics.initialize_farm(farm)  # Direct call!
end

# RIGHT
def register_farm(attrs) do
  farm = create_farm(attrs)
  broadcast(%FarmCreated{id: farm.id})     # Event
end
```

### 4. Law of Crash
> Pattern match. Let it crash. Trust the supervisor.

```elixir
# WRONG (defensive)
def process_request(farm_id) do
  case Repo.get(Farm, farm_id) do
    nil -> {:error, :not_found}
    farm -> do_work(farm)
  end
end

# RIGHT (for internal operations where farm MUST exist)
def process_request(farm_id) do
  %Farm{} = farm = Repo.get!(Farm, farm_id)
  do_work(farm)
end
```

### 5. Law of Result
> All fallible operations return `{:ok, _} | {:error, Context.Error.t() | Changeset.t()}`.

```elixir
# Public API returns tagged tuples with typed errors
@spec register_farm(map()) :: {:ok, Farm.t()} | {:error, Changeset.t()}
@spec get_farm(Ecto.UUID.t()) :: {:ok, Farm.t()} | {:error, Error.t()}

# Use `with` for chaining
with {:ok, farm} <- get_farm(farm_id),
     {:ok, policy} <- get_policy(farm),
     {:ok, _} <- authorize(farmer, farm) do
  {:ok, farm}
end
```

**Error types**:
- `Ecto.Changeset.t()` for validation failures (field-level detail)
- `Context.Error.t()` for domain errors (business logic, not found, auth)

### 6. Law of Specification
> Every public function has `@doc` and `@spec`.

```elixir
@doc """
Revokes a farm's certificate, preventing future Hub access.

The farm can re-provision with a new key if needed.
"""
@spec revoke_certificate(farm_id :: Ecto.UUID.t()) ::
  {:ok, Certificate.t()} | {:error, :not_found | :already_revoked}
def revoke_certificate(farm_id) do
  # ...
end
```

### 7. Law of Simplicity
> Solve the problem at hand. No premature abstraction.

- No macros unless explicitly needed
- No GenServer unless state/messages required
- No event unless cross-context communication needed
- Boring is good

---

## Testing Checklist

### For Every Feature

```
□ Context facade has integration tests (database, full flow)
□ Schema changesets have unit tests (validation rules)
□ External dependencies are mocked via behaviours
□ Fixtures exist in test/support/fixtures/<context>/
□ Happy path tested
□ Error cases tested
□ Edge cases documented and tested
```

### Test Patterns

```elixir
# 1. Database tests use sandbox
setup do
  pid = Sandbox.start_owner!(Repo, shared: false)
  on_exit(fn -> Sandbox.stop_owner(pid) end)
  :ok
end

# 2. Mocks defined in test_helper.exs
Mox.defmock(HubClientMock, for: Gaia.FarmNode.HubConnection.Client)

# 3. Fixtures are modules
defmodule Gaia.Hub.CoopIdentity.FarmFixtures do
  def valid_attrs, do: %{name: "Test Farm", ...}
  def create_farm(attrs \\ %{}), do: ...
end
```

---

## Feature Checklist

Before marking a feature complete:

```
□ CIDER cycle complete (Context, Interface, Domain, Effect, React)
□ Placed in correct bounded context
□ Context has error.ex with typed reasons
□ Public API in context facade with @doc/@spec
□ Errors use Context.Error.t() or Ecto.Changeset.t()
□ No cross-context function calls (events only)
□ DataSharingPolicy checked if aggregating farm data
□ External dependencies behind behaviours
□ Tests written and passing
□ mix ci passes (tests, credo, format)
□ No defensive nil checks (pattern match instead)
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    GAIA FEATURE FRAMEWORK                       │
├─────────────────────────────────────────────────────────────────┤
│ CIDER: Context → Interface → Domain → Effect → React            │
├─────────────────────────────────────────────────────────────────┤
│ STRUCTURE:                                                      │
│   lib/<app>/<context>.ex           ← Facade (public API)        │
│   lib/<app>/<context>/error.ex     ← Context error struct       │
│   lib/<app>/<context>/<entity>.ex  ← Schema (data + validation) │
│   lib/<app>/<context>/<service>.ex ← Complex operations         │
│   lib/<app>/<context>/events/*.ex  ← Cross-context events       │
├─────────────────────────────────────────────────────────────────┤
│ ERRORS:                                                         │
│   {:error, Context.Error.t()}      ← Domain errors (not found,  │
│                                       auth, business rules)     │
│   {:error, Ecto.Changeset.t()}     ← Validation errors (fields) │
├─────────────────────────────────────────────────────────────────┤
│ CHAINING:    with {:ok, x} <- step1(), {:ok, y} <- step2()      │
│ MULTI-STEP:  Ecto.Multi for transactional DB operations         │
│ INJECTION:   Behaviour + Application.get_env + Mox              │
├─────────────────────────────────────────────────────────────────┤
│ LAWS:                                                           │
│   1. Autonomy     - Farm Node works offline                     │
│   2. Trust        - Data sharing is opt-in                      │
│   3. Boundaries   - Events, never direct calls                  │
│   4. Crash        - Pattern match, let supervisors handle       │
│   5. Result       - Typed errors per context                    │
│   6. Specification- @doc and @spec on public functions          │
│   7. Simplicity   - Boring is good                              │
├─────────────────────────────────────────────────────────────────┤
│ COMMANDS:                                                       │
│   mix ci                    ← Run before committing             │
│   mix test --cover          ← Run tests                         │
│   mix ecto.gen.migration X  ← New migration                     │
│   mix ecto.reset            ← Reset database                    │
└─────────────────────────────────────────────────────────────────┘
```

---

**Version**: 1.2  
**Created**: January 30, 2026  
**Updated**: January 30, 2026 - Added typed errors, event bus documentation
