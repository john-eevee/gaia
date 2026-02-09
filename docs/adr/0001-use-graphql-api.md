# 1. Use GraphQL as the Hub Interface Protocol

Date: 2026-02-05
Status: **Accepted**

## Context
Project Gaia aims to build a distributed smart agriculture system where the "Hub" (the central management software) is not a black box, but a replaceable component.

The system faces the following requirements:
1.  **Swappability (Resyndication):** A community of farmers must be able to replace the official Go implementation of the Hub with an alternative (e.g., Rust, Elixir, Python) without breaking their existing edge devices (Farms) or client tools.
2.  **Client Diversity:** The system must support the official Web Dashboard (SPA) while simultaneously enabling "Headless" operation via CLI tools, mobile apps, or third-party automation scripts created by farmers.
3.  **Bandwidth Constraints:** Farm environments often have poor connectivity. Clients need to request exact data requirements to minimize payload size (avoiding over-fetching).
4.  **Strict Contract:** There must be a clear, enforceable "Constitution" that defines what a Hub is, independent of the implementation code.

## Decision
We will use **GraphQL** as the primary API paradigm for the Hub, specifically adopting a **Schema-First** approach.

We will use the **[gqlgen](https://github.com/99designs/gqlgen)** library for the Go implementation to enforce strict typing and code generation based on the schema.

The GraphQL Schema (`.graphql` files) will reside in the shared `pkg/` directory and will serve as the canonical "Contract" of the system.

## Consequences

### Positive
* **The Schema is the Contract:** The GraphQL SDL (Schema Definition Language) acts as a machine-readable "Constitution." Any backend implementation can claim compliance by adhering to this schema.
* **Introspection:** Alternative clients can query the schema to discover capabilities dynamically, lowering the barrier for farmers building custom tools.
* **Efficient Data Loading:** Clients (especially mobile or IoT aggregators) can fetch complex nested data (e.g., `Farm -> Nodes -> Sensors -> LastReading`) in a single HTTP round-trip, which is critical for high-latency farm networks.
* **Type Safety:** Using `gqlgen` ensures that the Go implementation cannot drift from the defined schema. If the schema changes, the code fails to compile until the resolver is updated.

### Negative
* **Complexity:** Implementing GraphQL resolvers is more complex than writing simple REST handlers. We must manage **DataLoaders** to prevent the "N+1 Query Problem" (performance degradation when fetching nested lists).
* **Caching:** Standard HTTP caching (CDNs, browser cache) is more difficult to implement with GraphQL than with REST. We will need to rely on client-side caching (e.g., in the SPA) or persisted queries if performance becomes an issue.
* **Binary Data:** GraphQL is poor at handling file uploads/downloads. We will likely need a side-channel REST endpoint for large binary blobs (e.g., firmware updates, logs).

## Compliance
1.  The schema files must be stored in `pkg/graph/schema.graphql`.
2.  Any change to the API structure requires a Pull Request to the `pkg` module first.
3.  The `apps/hub` build pipeline must fail if the generated Go code is out of sync with the schema.
