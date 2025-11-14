# Bouncer - OCSP Certificate Validation Server

A lightweight, high-availability server that validates certificate status for reverse proxy authentication in the Gaia platform. Built with Elixir for exceptional concurrency and fault tolerance.

## Overview

Bouncer serves as a certificate validation service that responds directly to the reverse proxy with HTTP status codes:
- `200 OK` - Certificate is valid
- `412 Precondition Failed` - Certificate is revoked or unknown

The server is optimized for low latency and high throughput, making it suitable for deployment in front of critical authentication paths.

## Architecture

### Components

- **HTTP Server** - Built with Plug and Cowboy for efficient request handling
- **Database Layer** - Postgrex connection pool with read-only database access
- **Certificate Parser** - X.509 certificate serial extraction using the `x509` library
- **Telemetry** - Built-in metrics for request processing time and failure tracking

### Database Schema

The server expects a `certificate_status` table with the following structure:

```sql
CREATE TABLE certificate_status (
    user_uuid UUID NOT NULL,
    certificate_serial BIGINT PRIMARY KEY,
    status VARCHAR(20) NOT NULL CHECK (status IN ('valid', 'revoked'))
);

-- Create read-only user for the bouncer service
CREATE USER bouncer_ro WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE gaia TO bouncer_ro;
GRANT USAGE ON SCHEMA public TO bouncer_ro;
GRANT SELECT ON certificate_status TO bouncer_ro;
```

## Configuration

Configuration is managed through environment variables:

### Server Configuration
- `BOUNCER_PORT` - HTTP server port (default: 4000)

### Database Configuration
- `DB_HOST` - PostgreSQL hostname (default: localhost)
- `DB_PORT` - PostgreSQL port (default: 5432)
- `DB_NAME` - Database name (default: gaia)
- `DB_USER` - Database username (default: bouncer_ro)
- `DB_PASSWORD` - Database password (required in production)
- `DB_POOL_SIZE` - Connection pool size (default: 10)

## API Endpoints

### Health Check
```
GET /health
```

Returns `200 OK` if the server is running.

### Certificate Validation
```
POST /validate
Headers:
  X-Client-Cert: <PEM-encoded certificate>
```

Returns:
- `200 OK` - Certificate is valid
- `412 Precondition Failed` - Certificate is revoked or unknown
- `404 Not Found` - Invalid endpoint

## Telemetry

The server emits telemetry events for monitoring:

### Success Events
- Event: `[:bouncer, :request, :success]`
- Measurements: `%{duration: native_time}`
- Metadata: `%{status: 200 | 412}`

### Failure Events
- Event: `[:bouncer, :request, :failure]`
- Measurements: `%{duration: native_time}`
- Metadata: `%{}`

These events can be consumed by telemetry reporters like Prometheus, StatsD, or custom handlers.

## Development

### Prerequisites
- Elixir 1.14 or higher
- Erlang/OTP 25 or higher
- PostgreSQL 14 or higher

### Setup

```bash
# Install dependencies
cd bouncer
mix deps.get

# Compile the project
mix compile

# Run tests
mix test

# Run the server
mix run --no-halt
```

### Testing

```bash
# Run all tests
mix test

# Run with coverage
mix test --cover

# Run linting
mix credo

# Format code
mix format
```

### Manual Testing

```bash
# Health check
curl http://localhost:4000/health

# Certificate validation (example)
curl -X POST http://localhost:4000/validate \
  -H "X-Client-Cert: $(cat test_cert.pem)"
```

## Deployment

### Production Build

```bash
# Set environment to production
export MIX_ENV=prod

# Get dependencies and compile
mix deps.get --only prod
mix compile

# Create a release (optional)
mix release
```

### Docker Deployment

A Docker image can be built for containerized deployment:

```dockerfile
FROM elixir:1.14-alpine AS builder
WORKDIR /app
COPY mix.exs mix.lock ./
RUN mix deps.get --only prod
COPY . .
RUN mix compile

FROM elixir:1.14-alpine
WORKDIR /app
COPY --from=builder /app/_build/prod /app/_build/prod
COPY --from=builder /app/config /app/config
CMD ["mix", "run", "--no-halt"]
```

## Security Considerations

1. **Database Access** - The server uses a dedicated read-only database user
2. **Certificate Validation** - Only extracts serial numbers; does not perform full PKI validation
3. **Rate Limiting** - Should be implemented at the reverse proxy level
4. **Network Security** - Deploy behind a firewall; restrict access to authorized reverse proxies only

## Monitoring

Key metrics to monitor:

- Request rate (requests/second)
- Response latency (p50, p95, p99)
- Error rate (failed validations)
- Database connection pool utilization
- Certificate status distribution (valid vs revoked)

## Performance

The server is designed for high performance:

- Concurrent request handling via BEAM VM
- Connection pooling for database queries
- Minimal parsing overhead (serial extraction only)
- Sub-millisecond response times (typical)

Expected performance on modest hardware:
- **Throughput**: 10,000+ requests/second
- **Latency**: <5ms (p95)

## License

See [LICENSE](../LICENSE) file for details.
