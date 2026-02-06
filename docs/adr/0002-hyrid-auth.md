# 2. Hybrid Authentication (mTLS + JWT) & Database Revocation

Date: 2026-02-05
Status: **Accepted**

## Context
The Hub must serve two distinct classes of clients with contradictory security requirements:
1.  **Farms (Hardware):** Unattended, low-power devices. They require zero-touch authentication. mTLS (Mutual TLS) is the ideal standard here, as it authenticates the device at the connection layer using the hardware-burned identity.
2.  **Farmers & 3rd Party Tools (Humans/Software):** Web Dashboards, Mobile Apps, and custom scripts. These clients typically cannot manage client-side certificates easily and expect standard Token-based auth (JWT) over HTTPS.

**The Privacy Constraint:**
Project Gaia enforces a **"Privacy First"** architecture. Data resides on the Farm by default. The Hub is a shared aggregation point, not a master controller. Therefore, authentication as a "Farmer" (via JWT) must not grant unrestricted access to the live Farm, but *only* to data the farmer has explicitly chosen to export/syndicate to the Hub.

**The Conflict:**
Enforcing strict mTLS (`tls.RequireAndVerifyClientCert`) at the server level rejects all standard web clients. Additionally, maintaining an external OCSP responder contradicts the "single binary" deployment goal.

## Decision

We will implement a **Dual-Path Hybrid Authentication** system on a single HTTPS port with strict Data Scoping.

1.  **TLS Configuration:** The Hub will use `ClientAuth: tls.VerifyClientCertIfGiven`.
2.  **Application-Layer Gating:** We will implement a unified Authentication Middleware:
    * **Path A (Hardware):** If a valid Client Certificate is present, the identity is resolved as `Role: NODE`.
    * **Path B (Software):** If a valid JWT is present, the identity is resolved as `Role: FARMER`.
3.  **Local Revocation:** We will "blocklist" certificates using the Hub's local database, checking serial numbers against a `revocations` table.

### Data Scoping & Privacy Rule
Authentication does not imply data visibility. The Hub enforces a strict separation:
* **The Hub is NOT a Proxy:** The Hub API will not forward queries to the live Farm to fetch private data.
* **Export-Only Access:** A user authenticated as `FARMER` can only query data that has been **previously synchronized/exported** from the Node to the Hub (e.g., aggregated yields, public proposals).
* **Private by Default:** Granular sensor logs, private journals, or raw operational data remaining on the Node are cryptographically inaccessible to the Hub's JWT scope.

## Detailed Flow

### 1. The Revocation Check
* **Table:** `certificates` (columns: `serial_number`, `node_id`, `status`).
* **Logic:** If `cert_serial` is in the local blocklist cache, abort connection (403).

### 2. The Identity Resolution
* **If Cert Valid:** `Context.User = { Type: "NODE", ID: Cert.CommonName }`
* **If JWT Valid:** `Context.User = { Type: "FARMER", ID: Token.Sub, Scope: "EXPORTED_DATA_ONLY" }`
* **If Neither:** `Context.User = { Type: "GUEST" }`

## Consequences

### Positive
* **Privacy Compliance:** The architecture technically guarantees that the Hub cannot be used to spy on a farm's private operations. Even if a Hub admin compromises the server, they only see data the farmer voluntarily exported.
* **Unified Endpoint:** Simplifies network config (single port) while supporting both Hardware (mTLS) and Software (JWT) clients.
* **Zero-Infrastructure Revocation:** No external OCSP responder required.

### Negative
* **Data Staleness:** Since the Farmer only sees exported data, the Dashboard might show slightly outdated information compared to the live physical node.
* **Replay Risk (JWT):** Unlike mTLS, JWTs can be stolen. However, the scope of a stolen JWT is limited to public/syndicated data, not the farm's private control systems.

## Compliance
1.  All GraphQL resolvers must check the data source. If a query requires live data from a Node, it must be rejected for JWT users.
2.  The `revocations` cache must have a short TTL (e.g., 5 minutes).
