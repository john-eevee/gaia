This file provides the mandatory rules, context, and security principles for any AI agent or developer contributing to the **Project Gaia Hub Application**.

You MUST adhere to these guidelines to ensure the security, stability, and integrity of the cooperative's central system.

---

## 1. Project Mission & Core Goals

* **Project:** Project Gaia, a "Smart Agriculture Cooperative."
* **This Application:** This is the **Co-op Hub**, the central cluster of Elixir nodes.
* **Mission:** The Hub provides shared services that individual farms (`Farm Nodes`) cannot manage alone. It facilitates cooperation.
* **Core Principles:**
    1.  **Farmer Autonomy:** The Hub provides *enhancements* (analytics, market access), not *life support*. `Farm Nodes` are autonomous and may disconnect. All Hub APIs must be asynchronous and tolerant of failure and latency.
    2.  **Explicit Trust:** Security and data governance are our foundation. Data is owned by the farmer. All data sharing is **opt-in by default** (`share_nothing`).

## 2. Bounded Contexts (Do Not Cross!)

This application is built using Domain-Driven Design (DDD). You MUST respect these boundaries.

* `CoopIdentity`: Manages members, farms, data sharing policies, and all security credentials. **This is the system's gatekeeper.**
* `RegionalAnalytics`: Ingests *permissioned* data from farms to find regional trends.
* `SharedResources`: Manages booking/scheduling of co-op-owned equipment.
* `Marketplace`: A unified sales channel (SupplyOffers from farms, CustomerOrders from buyers).
* `GroupProcurement`: Manages bulk purchasing of supplies for members.

**Agent Rule:** You MUST NOT write code that makes a direct function call from one context to another. (e.g., `Marketplace` cannot call `RegionalAnalytics.ingest_data()`).

**How to Communicate:** Use `Phoenix.PubSub`.
* **Correct:** `Marketplace` broadcasts `{:offer_created, offer}`. `RegionalAnalytics` subscribes to this topic and handles it.
* **Incorrect:** `Marketplace.create_offer(params)` calls `RegionalAnalytics.track_offer(offer)`.

---

## 3. Mandatory Security Flow & Rules

This is the most critical part of the Hub. Failure here compromises the entire co-op.

### Rule 1: Authentication is mTLS

All endpoints for `Farm Nodes` (except the provisioning endpoint) MUST be protected by **Mutual TLS (mTLS)**. The `Farm Node` must present a valid client certificate signed by our internal Certificate Authority (CA).

### Rule 2: Provisioning (The ONLY Exception)

This is the one flow that does *not* use mTLS.

1.  **Out-of-Band:** An admin manually creates a `FarmMember` in the `Co-opIdentity` context.
2.  **Key Generation:** The Hub generates a secure, single-use **`InitialProvisioningKey`**.
3.  **The Endpoint:** You will work on a single, public, non-mTLS endpoint (e.g., `/api/v1/provision`).
4.  **The Exchange:**
    * Node sends its `InitialProvisioningKey`.
    * The Hub validates the key.
    * The Hub *immediately invalidates the key* to prevent reuse.
    * The Hub's internal CA generates and signs a new client certificate for that `FarmMember`.
    * The Hub returns this certificate to the Node.
    * All future communication from the Node MUST use this certificate.

### Rule 3: Revocation is Decoupled (OCSP)

We use a real-time, decoupled revocation system.

* **Your Job (The Context):** The `Co-opIdentity` context *manages* the revocation status. You will write the code for the admin panel, where an admin clicks "Revoke." This action MUST update the status of the certificate (e.g., `status: "revoked"`) in the `CertificateRegistry` database table.
* **NOT Your Job (The Check):** You MUST NOT write any Elixir code in the application (e.g., a Plug) to *check* for revocation. This is handled at the network edge by our reverse proxy, which queries a separate, decoupled **OCSP Responder** service. That responder reads the database table you manage.

---

## 4. Elixir & Phoenix Best Practices

### 1. Contexts are the API
All business logic MUST live in a context module (e.g., `Gaia.Marketplace`) or in service module within the context (e.g. `Gaia.Marketplace.SupplyOffer`) that will be exposed using the context API.
All database access MUST go through a function in its context (e.g., `Marketplace.list_offers()`). Do NOT use Ecto functions directly from a Phoenix controller.

### 2. Schemas are Data, Not Logic
Ecto schemas (e.g., `Gaia.Marketplace.Offer`) define data structures and changesets for validation. They MUST NOT contain business logic.

### 3. Always Check `DataSharingPolicy`
This is a **CRITICAL STAKEHOLDER RULE**. Any function you write that aggregates data from multiple farms (e.g., in `RegionalAnalytics`) MUST check the `DataSharingPolicy` for *each* farm involved. The default is `share_nothing`. You must explicitly query for permission *before* including a farm's data in an aggregate.

### 4. Use Tuples and Pattern Matching
* Do not return `nil`. Return `{:ok, value}` or `{:error, reason}`.
* Use pattern matching in function heads to enforce correct data.
* Use guard clauses (`when`) for validation.

**Good:**
```elixir
def get_offer(id, %DataSharingPolicy{allow_market_read: true}) do
  # ... logic
end

def get_offer(_, %DataSharingPolicy{allow_market_read: false}) do
  {:error, :unauthorized}
end

```

### 5. . Do Not Fear Crashes

Write code that is explicit. Do not defensively code against nil values. Trust the supervision tree. If a FarmMember should exist for a given request, pattern match on it. If it's nil, let the process crash so the supervisor can handle it. This is safer than processing a request in an invalid state.
