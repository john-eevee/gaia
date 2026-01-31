This file provides the mandatory rules, context, and best practices for any AI agent or developer contributing to the **Bouncer OCSP Certificate Validation Server**.

You MUST adhere to these guidelines to ensure the security, reliability, and maintainability of this critical authentication component.

---

## 1. Project Mission & Core Goals

* **Project:** Project Gaia, a "Smart Agriculture Cooperative."
* **This Application:** This is **Bouncer**, the OCSP-like certificate validation server.
* **Mission:** Bouncer provides real-time certificate revocation checking for the reverse proxy layer, ensuring only valid, non-revoked certificates can access the Gaia platform.
* **Core Principles:**
    1. **Security First:** This service is a critical security component. Any bug or vulnerability here compromises the entire platform's authentication system.
    2. **High Availability:** The service must be available 24/7 with sub-5ms response times. Downtime means authentication failures for all farm nodes.
    3. **Simplicity:** Keep the codebase minimal and focused. This is a single-purpose service with no business logic complexity.
    4. **Read-Only Operations:** The service only reads certificate status; it never writes to the database.

## 2. Architecture Constraints

### Single Responsibility

Bouncer has ONE job: check if a certificate serial number is revoked. Do NOT add additional features like:
- Certificate issuance or management
- User authentication beyond certificate validation
- Business logic or data aggregation
- File uploads or downloads

If you need these features, they belong in a different service (likely the Hub's `CoopIdentity` context).

### Stateless Design

Bouncer is completely stateless. All state is in the PostgreSQL database. This means:
- No in-memory caching of certificate status (cache invalidation is complex and error-prone)
- No session management
- No local file storage
- Each request is independent and can be served by any Bouncer instance

### Database Access Pattern

**CRITICAL:** Bouncer uses a dedicated read-only database user (`bouncer_ro`) with SELECT-only permissions on a single table (`certificate_status`).

```sql
-- This is the ONLY table Bouncer queries
CREATE TABLE certificate_status (
    user_uuid UUID NOT NULL,
    certificate_serial VARCHAR(64) PRIMARY KEY,  -- Certificate serial as hexadecimal string
    status BOOLEAN NOT NULL  -- true (1) = valid, false (0) = revoked
);
```

**Rules:**
- NEVER write SQL that modifies data (INSERT, UPDATE, DELETE)
- NEVER access any other tables
- NEVER bypass the read-only user with elevated credentials
- Keep queries simple: `SELECT status WHERE certificate_serial = $1`

---

## 3. Mandatory Security Rules

### Rule 1: Input Validation

The service receives PEM-encoded certificates from the reverse proxy via the `X-Client-Cert` header.

**You MUST:**
- Validate that the header exists and is non-empty
- Parse the certificate using the `X509` library (already validated and maintained)
- Extract only the serial number (do not store or log the full certificate)
- Handle parsing errors gracefully (return 412, not 500)

**You MUST NOT:**
- Accept certificate serial numbers directly (always parse from PEM)
- Trust any other input without validation
- Log sensitive certificate data (except serial numbers for debugging)

### Rule 2: Error Handling

Bouncer operates in a "fail-closed" security model:

- **Certificate parsing fails?** → Return `412 Precondition Failed`
- **Certificate not in database?** → Return `412 Precondition Failed`
- **Certificate status is 'revoked'?** → Return `412 Precondition Failed`
- **Certificate status is 'valid'?** → Return `200 OK`
- **Database connection error?** → Return `503 Service Unavailable` (let supervisor restart)

**Never return `200 OK` unless you have successfully verified the certificate is valid.**

### Rule 3: Logging and Observability

- **Log all validation failures** with the certificate serial number and reason
- **Emit telemetry events** for every request (duration, success/failure)
- **Do NOT log** full certificates, private keys, or database credentials
- Use structured logging (JSON format in production)

---

## 4. Elixir & Plug Best Practices

### 1. Let It Crash

This service is mission-critical but also extremely simple. Follow Elixir's "let it crash" philosophy:

- Do NOT defensively check for `nil` in places where data should exist
- Let processes crash on unexpected input
- Trust the OTP supervisor to restart failed processes
- The supervisor tree will handle GenServer failures

**Good:**
```elixir
def check_certificate_status(serial) when is_integer(serial) do
  GenServer.call(__MODULE__, {:check_status, serial})
end
```

**Bad:**
```elixir
def check_certificate_status(serial) do
  if is_nil(serial) do
    {:error, :invalid_input}
  else
    # ... defensive checks ...
  end
end
```

### 2. Use Pattern Matching

Pattern match on database results to make the code explicit and safe:

```elixir
case Postgrex.query(conn, query, [serial]) do
  {:ok, %Postgrex.Result{rows: [[status]]}} ->
    {:ok, normalize_status(status)}
  
  {:ok, %Postgrex.Result{rows: []}} ->
    {:ok, :unknown}
  
  {:error, reason} ->
    Logger.error("Database query failed: #{inspect(reason)}")
    {:error, reason}
end
```

### 3. Keep It Simple

This codebase should remain under 1,000 lines of Elixir. If you find yourself writing complex abstractions, stop and reconsider.

**Avoid:**
- Custom DSLs or macro magic
- Complex GenServer state machines
- Multi-step workflows
- Background jobs or async processing

**Prefer:**
- Direct, simple function calls
- Synchronous request/response
- Minimal dependencies

### 4. Telemetry is Mandatory

Every HTTP request MUST emit telemetry events:

```elixir
:telemetry.execute(
  [:bouncer, :request, :success],
  %{duration: duration},
  %{status: status_code}
)
```

These events are consumed by monitoring systems. Without them, we are blind to failures.

---

## 5. Testing Requirements

### Unit Tests

Every module must have tests. Focus on:

- Certificate parsing (valid PEM, invalid PEM, malformed data)
- Database queries (valid certificate, revoked certificate, unknown certificate)
- HTTP routing (health check, validate endpoint, 404 handling)
- Error conditions (database down, invalid input)

### Integration Tests

Use the test database to verify:
- End-to-end request flow (PEM → parse → query → response)
- Database connection pooling
- Telemetry event emission

**DO NOT:**
- Mock the database (use a real test database)
- Skip tests because "it's simple"
- Test against production data

### CI Requirements

The CI suite (`mix ci`) must pass before merging any code:

```bash
mix ci  # Runs: deps.get, compile --warnings-as-errors, test --cover, credo, format --check-formatted, deps.audit
```

All warnings must be fixed. Code coverage should remain above 80%.

---

## 6. Performance Guidelines

### Expected Performance

On modest hardware (4 cores, 8GB RAM):
- **Throughput:** 10,000+ requests/second
- **Latency (p95):** <5ms
- **Database connections:** Pool of 10-50 (configurable)

### Optimization Rules

**DO:**
- Use connection pooling (Postgrex handles this)
- Keep database queries simple (single SELECT with primary key lookup)
- Use prepared statements (Postgrex does this automatically)

**DO NOT:**
- Add in-memory caching (state management is complex and error-prone)
- Implement rate limiting (that's the reverse proxy's job)
- Add background processing or queues
- Perform complex calculations in the request path

### Load Testing

Before deploying changes that touch the request path, run load tests:

```bash
# Example using Apache Bench
ab -n 10000 -c 100 http://localhost:4444/health
```

Performance should not regress by more than 10% compared to the previous version.

---

## 7. Deployment Rules

### Environment Variables

All configuration MUST use environment variables. Never hardcode:
- Database credentials
- Port numbers
- Hostnames

### Docker Images

The production Docker image uses a multi-stage build with `mix release`:

1. Build stage: Compile code and create release
2. Runtime stage: Minimal Alpine image with release binary

**DO NOT:**
- Ship the full Elixir runtime in production
- Include development dependencies
- Include source code in the runtime image

### Database Migrations

This service does NOT handle migrations. The `certificate_status` table is managed by the Hub application. Bouncer only reads from it.

If the schema changes, coordinate with the Hub team first.

---

## 8. Contributing Workflow

1. **Read this file first** before making any changes
2. **Write tests** for your changes
3. **Run `mix ci`** locally before pushing
4. **Keep commits small** and focused (one logical change per commit)
5. **Write clear commit messages** (what changed and why)
6. **Request code review** from the maintainer

### Code Review Checklist

Before requesting review, verify:
- [ ] All tests pass
- [ ] No compiler warnings
- [ ] Code is formatted (`mix format`)
- [ ] Credo checks pass (`mix credo`)
- [ ] Security audit passes (`mix deps.audit`)
- [ ] Documentation is updated (if needed)
- [ ] Telemetry events are emitted
- [ ] Error handling follows "fail-closed" model

---

## 9. What NOT to Build

To keep Bouncer focused, do NOT implement:

- ❌ Certificate issuance or signing
- ❌ Certificate revocation (that's the Hub's responsibility)
- ❌ User management or authentication
- ❌ Admin UI or dashboard
- ❌ Metrics aggregation (use external tools like Prometheus)
- ❌ Log aggregation (use external tools like ELK/Loki)
- ❌ Rate limiting or DDoS protection (use reverse proxy)
- ❌ Batch processing or background jobs
- ❌ Webhooks or external notifications
- ❌ Multi-tenancy or complex access control

If you need any of these features, they belong in a different service or should be handled by infrastructure (reverse proxy, monitoring systems, etc.).

---

## 10. Getting Help

- **Security Issues:** Report immediately to the security team
- **Bug Reports:** Open an issue with reproduction steps
- **Feature Requests:** Discuss in an issue before implementing
- **Questions:** Check the documentation in `docs/` first

Remember: Bouncer is a security-critical, single-purpose service. When in doubt, keep it simple and ask for guidance.
