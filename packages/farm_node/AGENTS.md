# Usage Rules

**IMPORTANT**: Consult these usage rules early and often when working with the packages listed below.
Before attempting to use any of these packages or to discover if you should use them, review their
usage rules to understand the correct patterns, conventions, and best practices.
## usage_rules usage
_A dev tool for Elixir projects to gather LLM usage rules from dependencies_

## Using Usage Rules

Many packages have usage rules, which you should *thoroughly* consult before taking any
action. These usage rules contain guidelines and rules *directly from the package authors*.
They are your best source of knowledge for making decisions.

## Modules & functions in the current app and dependencies

When looking for docs for modules & functions that are dependencies of the current project,
or for Elixir itself, use `mix usage_rules.docs`

# Search a whole module

mix usage_rules.docs Enum

# Search a specific function

mix usage_rules.docs Enum.zip



## Searching Documentation

You should also consult the documentation of any tools you are using, early and often. The best
way to accomplish this is to use the `usage_rules.search_docs` mix task.

## usage_rules:elixir usage
# Elixir Core Usage Rules

## Pattern Matching
- Use pattern matching over conditional logic when possible
- Prefer to match on function heads instead of using `if`/`else` or `case` in function bodies
- `%{}` matches ANY map, not just empty maps. Use `map_size(map) == 0` guard to check for truly empty maps

## Error Handling
- Use `{:ok, result}` and `{:error, reason}` tuples for operations that can fail
- Avoid raising exceptions for control flow
- Use `with` for chaining operations that return `{:ok, _}` or `{:error, _}`

## Common Mistakes to Avoid
- Elixir has no `return` statement, nor early returns. The last expression in a block is always returned.
- Don't use `Enum` functions on large collections when `Stream` is more appropriate
- Avoid nested `case` statements - refactor to a single `case`, `with` or separate functions
- Don't use `String.to_atom/1` on user input (memory leak risk)
- Lists and enumerables cannot be indexed with brackets. Use pattern matching or `Enum` functions
- Prefer `Enum` functions like `Enum.reduce` over recursion
- When recursion is necessary, prefer to use pattern matching in function heads for base case detection
- Using the process dictionary is typically a sign of unidiomatic code
- Only use macros if explicitly requested

## Function Design
- Use guard clauses: `when is_binary(name) and byte_size(name) > 0`
- Prefer multiple function clauses over complex conditional logic
- Name functions descriptively: `calculate_total_price/2` not `calc/2`
- Predicate function names should not start with `is` and should end in a question mark.
- Names like `is_thing` should be reserved for guards

## Mix Tasks
- Use `mix help` to list available mix tasks
- Use `mix help task_name` to get docs for an individual task

## Testing
- Run tests in a specific file with `mix test test/my_test.exs` and a specific test with the line number `mix test path/to/test.exs:123`
- Limit the number of failed tests with `mix test --max-failures n`
- Use `assert_raise` for testing expected exceptions

## Debugging
- Use `dbg/1` to print values while debugging.

## usage_rules:otp usage
# OTP Usage Rules

## GenServer Best Practices
- Keep state simple and serializable
- Handle all expected messages explicitly
- Use `handle_continue/2` for post-init work
- Implement proper cleanup in `terminate/2` when necessary

## Process Communication
- Use `GenServer.call/3` for synchronous requests expecting replies
- Use `GenServer.cast/2` for fire-and-forget messages.
- When in doubt, use `call` over `cast`, to ensure back-pressure
- Set appropriate timeouts for `call/3` operations

## Fault Tolerance
- Set up processes such that they can handle crashing and being restarted by supervisors
- Use `:max_restarts` and `:max_seconds` to prevent restart loops
- **Specific to Farm Node:** Processes interacting with hardware (Sensors/Devices) must handle physical disconnections gracefully without crashing the entire supervision tree.

----

## 1. Project Mission & Core Goals

* **Project:** Project Gaia, a "Smart Agriculture Cooperative."
* **This Application:** This is the **Farm Node**, the software running on local, independent farm servers.
* **Mission:** Manage local farm operations, integrate with hardware/sensors, and autonomously make decisions.
* **Core Principles:**
    1.  **Offline-First Autonomy:** This node MUST remain fully functional (e.g., irrigation, alerts, rules engine) even if the internet connection to the Hub is severed. The Hub is an enhancement, not a dependency.
    2.  **Privacy by Design:** Data generated here belongs to the farmer. No data leaves this node unless specifically allowed by the `DataSharingPolicy`.

## 2. Environment and CLI

Use the following commands when creating files or running tasks:

- `mix ecto.reset`: Resets the local SQLite/Postgres database.
- `mix ci`: Runs the entire CI suite (tests, linting).
- `mix test --cover`: Runs tests with coverage (do not use LSP/DAP for this).
- `mix ecto.gen.migration {name}`: Generates a migration file.

## 3. Bounded Contexts

This application is built using Domain-Driven Design (DDD). You MUST respect these boundaries.

You MUST NOT write code that makes a direct function call from one context to another.
* **Exception:** `LocalRules` may query `FarmOperations` for read-only state (e.g., getting field boundaries), but writes must happen via Commands/Events.

**Context Definitions:**
* `FarmOperations`: Manages fields, crop batches, and tasks.
* `DeviceManagement`: Manages the "private fleet" of IoT devices (sensors, drones). Handles telemetry ingestion.
* `LocalRules`: The immediate-response engine. Consumes telemetry, evaluates rules (e.g., "If dry, water"), and issues commands.
* `HubConnection`: Manages the secure link to the Co-op Hub, authentication (mTLS), and data synchronization.

## 3.1. Cross Boundary Communication
- Events are structs where the payload are the struct fields.
- Events must implement the `Gaia.Event` protocol.
- Use `Gaia.Event` protocol with `Phoenix.PubSub` to publish the event data structure.

**Example:**
```elixir
defmodule TelemetryReceived do
  use Gaia.Event
  defstruct :device_id, :reading, :timestamp
end
```
# In DeviceManagement context
event = %TelemetryReceived{device_id: "sensor-1", reading: 12.5, timestamp: DateTime.utc_now()}
Phoenix.PubSub.broadcast(Gaia.PubSub, Gaia.Event.topic(event), Gaia.Event.payload(event))



## 4. Mandatory Security & Connectivity Rules

### Rule 1: The Secure Handshake (Provisioning)

On the very first boot, the Node has no identity.

1. **Prompt:** The Node must accept an `InitialProvisioningKey` and `HubAddress` (via CLI or UI).
2. **Request:** The `HubConnection` context sends a request to the Hub's public `/api/v1/provision` endpoint.
3. **Storage:** The response contains a permanent mTLS Certificate and Private Key. These MUST be stored securely (e.g., `priv/ssl/` or encrypted storage), NOT in the database or Git.
4. **Usage:** All future HTTP clients (e.g., Tesla/Mint) must load these files to authenticate.

### Rule 2: mTLS Authenticated Heartbeat

* The Node must maintain a periodic "Heartbeat" (e.g., every 5 minutes) to the Hub.
* If the Hub responds `403 Forbidden` (Certificate Revoked), the Node MUST immediately cease all data transmission and alert the local user.

### Rule 3: Data Sharing Enforcement

* **Default:** The default `DataSharingPolicy` is `share_nothing`.
* **Enforcement:** Before the `HubConnection` context pushes *any* event (e.g., `PestSighting`) to the Hub, it MUST check the local `DataSharingPolicy`.
* **Pattern:**
* `LocalRules` detects a pest -> Publishes `LocalAlertTriggered`.
* `HubConnection` listens to `LocalAlertTriggered`.
* `HubConnection` checks: `if Policy.share_pest_sightings?() == true`, THEN push to Hub. ELSE ignore.



## 5. Hardware Integration Guidelines

* **Simulation:** Use GenServers to simulate hardware when physical devices are absent.
* **Resilience:** Hardware fails. A crash in a sensor driver MUST NOT crash the `LocalRules` engine or the web UI. Use `DynamicSupervisor` for device processes.

---

Write code that is explicit. Do not defensively code against nil values. Trust the supervision tree.

