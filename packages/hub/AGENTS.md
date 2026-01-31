<!-- usage-rules-start -->
<!-- usage-rules-header -->
# Usage Rules

**IMPORTANT**: Consult these usage rules early and often when working with the packages listed below.
Before attempting to use any of these packages or to discover if you should use them, review their
usage rules to understand the correct patterns, conventions, and best practices.
<!-- usage-rules-header-end -->

<!-- usage_rules-start -->
## usage_rules usage
_A dev tool for Elixir projects to gather LLM usage rules from dependencies_

## Using Usage Rules

Many packages have usage rules, which you should *thoroughly* consult before taking any
action. These usage rules contain guidelines and rules *directly from the package authors*.
They are your best source of knowledge for making decisions.

## Modules & functions in the current app and dependencies

When looking for docs for modules & functions that are dependencies of the current project,
or for Elixir itself, use `mix usage_rules.docs`

```
# Search a whole module
mix usage_rules.docs Enum

# Search a specific function
mix usage_rules.docs Enum.zip

# Search a specific function & arity
mix usage_rules.docs Enum.zip/1
```


## Searching Documentation

You should also consult the documentation of any tools you are using, early and often. The best
way to accomplish this is to use the `usage_rules.search_docs` mix task. Once you have
found what you are looking for, use the links in the search results to get more detail. For example:

```
# Search docs for all packages in the current application, including Elixir
mix usage_rules.search_docs Enum.zip

# Search docs for specific packages
mix usage_rules.search_docs Req.get -p req

# Search docs for multi-word queries
mix usage_rules.search_docs "making requests" -p req

# Search only in titles (useful for finding specific functions/modules)
mix usage_rules.search_docs "Enum.zip" --query-by title
```


<!-- usage_rules-end -->
<!-- usage_rules:elixir-start -->
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
- There are many useful standard library functions, prefer to use them where possible

## Function Design
- Use guard clauses: `when is_binary(name) and byte_size(name) > 0`
- Prefer multiple function clauses over complex conditional logic
- Name functions descriptively: `calculate_total_price/2` not `calc/2`
- Predicate function names should not start with `is` and should end in a question mark.
- Names like `is_thing` should be reserved for guards

## Data Structures
- Use structs over maps when the shape is known: `defstruct [:name, :age]`
- Prefer keyword lists for options: `[timeout: 5000, retries: 3]`
- Use maps for dynamic key-value data
- Prefer to prepend to lists `[new | list]` not `list ++ [new]`

## Mix Tasks

- Use `mix help` to list available mix tasks
- Use `mix help task_name` to get docs for an individual task
- Read the docs and options fully before using tasks

## Testing
- Run tests in a specific file with `mix test test/my_test.exs` and a specific test with the line number `mix test path/to/test.exs:123`
- Limit the number of failed tests with `mix test --max-failures n`
- Use `@tag` to tag specific tests, and `mix test --only tag` to run only those tests
- Use `assert_raise` for testing expected exceptions: `assert_raise ArgumentError, fn -> invalid_function() end`
- Use `mix help test` to for full documentation on running tests

## Debugging

- Use `dbg/1` to print values while debugging. This will display the formatted value and other relevant information in the console.

<!-- usage_rules:elixir-end -->
<!-- usage_rules:otp-start -->
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

## Task and Async
- Use `Task.Supervisor` for better fault tolerance
- Handle task failures with `Task.yield/2` or `Task.shutdown/2`
- Set appropriate task timeouts
- Use `Task.async_stream/3` for concurrent enumeration with back-pressure

<!-- usage_rules:otp-end -->
<!-- usage-rules-end -->

----


## 1. Project Mission & Core Goals

* **Project:** Project Gaia, a "Smart Agriculture Cooperative."
* **This Application:** This is the **Coop Hub**, the central cluster of Elixir nodes.
* **Mission:** The Hub provides shared services that individual farms (`Farm Nodes`) cannot manage alone. It facilitates cooperation.
* **Core Principles:**
    1.  **Farmer Autonomy:** The Hub provides *enhancements* (analytics, market access), not *life support*. `Farm Nodes` are autonomous and may disconnect. All Hub APIs must be asynchronous and tolerant of failure and latency.
    2.  **Explicit Trust:** Security and data governance are our foundation. Data is owned by the farmer. All data sharing is **opt-in by default** (`share_nothing`).


## 2. Environment and CLI

Use the following commands when creating files or running tasks

- `mix ecto.reset`: resets the database and brings it up again
- `mix ci`: runs the entire ci suite, including tests and linting,
 use when finished with changes.
- `mix test --cover`: command to use for tests, do not use LSP or DAP
- `mix ecto.gen.migration {name}`: generate a migration file with

## 3. Bounded Contexts

This application is built using Domain-Driven Design (DDD). You MUST respect these boundaries.

You MUST NOT write code that makes a direct function call from one context to another. (e.g., `Marketplace` cannot call `RegionalAnalytics.ingest_data()`).

Each public function in a context is considered a use case. They avoid temporal
coupling for the user.

Each public function should be documented appropriately

## 3.1. Cross Boundary Communication
- Events are structs where the payload are the struct fields.
- Events must implement the `Gaia.Event` protocol.
- Use `Gaia.Event` protocol with Phoenix.PubSub to publish the event data-strcture

Exemple:

```elixir
defmodule FarmCreated do
 use Gaia.Event
 defstruct :id, :name
end

# somewhere else
event = %FarmCreated{id: "my-id", name: "my-name"}
Phoenix.PubSub.broadcast(MyPubSub, Gaia.Event.topic(event), Gaia.Event.payload(event))
```

## 4. Mandatory Security Flow & Rules

This is the most critical part of the Hub. Failure here compromises the entire coop.

### Rule 1: Authentication is mTLS

All endpoints for `Farm Nodes` (except the provisioning endpoint) MUST be protected by **Mutual TLS (mTLS)**. The `Farm Node` must present a valid client certificate signed by our internal Certificate Authority (CA).

### Rule 2: Provisioning (The ONLY Exception)

This is the one flow that does *not* use mTLS.

1.  **Out-of-Band:** An admin manually creates a `Farm` in the `CoopIdentity` context.
2.  **Key Generation:** The Hub generates a secure, single-use **`InitialProvisioningKey`**.
3.  **The Endpoint:** You will work on a single, public, non-mTLS endpoint (e.g., `/api/v1/provision`).
4.  **The Exchange:**
    * Node sends its `InitialProvisioningKey`.
    * The Hub validates the key.
    * The Hub *immediately invalidates the key* to prevent reuse.
    * The Hub's internal CA generates and signs a new client certificate for that `Farm`.
    * The Hub returns this certificate to the Node.
    * All future communication from the Node MUST use this certificate.

### 5. Always Check `DataSharingPolicy`
This is a **CRITICAL STAKEHOLDER RULE**. Any function you write that aggregates data from multiple farms (e.g., in `RegionalAnalytics`) MUST check the `DataSharingPolicy` for *each* farm involved. The default is `share_nothing`. You must explicitly query for permission *before* including a farm's data in an aggregate.
----

Write code that is explicit. Do not defensively code against nil values. Trust the supervision tree. If a Farm should exist for a given request, pattern match on it. If it's nil, let the process crash so the supervisor can handle it. This is safer than processing a request in an invalid state.
