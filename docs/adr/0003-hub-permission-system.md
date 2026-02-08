# 3. Hub Permission System and Role-Based Access Control (RBAC)

Date: 2026-02-06
Status: **Proposed**

## Context
The Hub serves as the central management point for the Project Gaia cooperative. As identified in [ADR 0002](./0002-hyrid-auth.md), the Hub must support multiple classes of clients (Farms, Farmers, and 3rd Party Tools). To ensure secure operations and maintain data sovereignty, a robust permission system is required to govern what actions each entity can perform on the Hub.

The system needs to distinguish between administrative tasks, day-to-day operations, farmer-specific data management, and automated tool access.

## Decision
We will implement a **Role-Based Access Control (RBAC)** system for the Hub. 

### Core Rules
1.  **Mandatory Roles:** Every authenticated user or entity MUST have at least one assigned role. The system will reject requests from identities without an associated role.
2.  **Explicit Mapping:** Roles will be assigned during the authentication/provisioning phase and embedded in the security context (JWT claims or mTLS certificate mapping).

### Available Roles
*   **ADMIN:** The system superuser.
    *   *Capabilities:* Full access to system configuration, infrastructure maintenance, management of provision keys, and adding/removing Farm nodes.
*   **FARMER:** The primary account for cooperative members.
    *   *Capabilities:* Access to their own farm's aggregated data, participation in cooperative proposals, and management of their personal settings and export preferences.
*   **TOOL:** Third-party API clients.
    *   *Capabilities:* Acts on behalf of a Farmer with a scoped set of permissions. This allows for automation and external integrations without sharing primary Farmer credentials.
*   **CLERK:** Cooperative employees.
    *   *Capabilities:* Management of day-to-day cooperative operations, such as inventory tracking, basic member support, and report generation, without access to system-level configuration (ADMIN tasks).

## Consequences

### Positive
*   **Security:** Enforces the principle of least privilege.
*   **Clarity:** Provides a clear mental model for developers when implementing GraphQL resolvers and middleware.
*   **Extensibility:** New roles can be defined as the cooperative's organizational structure evolves.

### Negative
*   **Complexity:** Requires careful implementation of middleware to check roles on every API request.
*   **Management Overhead:** Requires UI/CLI tools for administrators to manage role assignments and Clerk/Farmer accounts.

## Compliance
1.  The GraphQL middleware must validate the presence of a role in the request context.
2.  All mutation resolvers must explicitly check if the current user's role is authorized for the specific action.
3.  Integration tests must be written to verify that unauthorized roles are blocked from sensitive endpoints.
