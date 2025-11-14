# Bouncer - OCSP Certificate Validation Server

A lightweight, high-availability server that validates certificate status for reverse proxy authentication in the Gaia platform. Built with Elixir for exceptional concurrency and fault tolerance.

## What is Bouncer?

Bouncer is a dedicated OCSP-like service that responds to reverse proxy authentication requests with:
- `200 OK` - Certificate is valid
- `412 Precondition Failed` - Certificate is revoked or unknown

It queries a PostgreSQL database to check certificate status in real-time, providing sub-5ms latency with support for 10,000+ requests/second.

## Quick Start

### Using Docker Compose (Recommended)

```bash
cd bouncer
docker-compose up -d

# Verify it's running
curl http://localhost:4444/health
```

This starts both Bouncer and a PostgreSQL database with the required schema.

### Running Locally

**Prerequisites:** Elixir 1.19+, Erlang/OTP 28+, PostgreSQL 14+

```bash
# Install dependencies
cd bouncer
mix deps.get

# Set environment variables
export BOUNCER_PORT=4444
export DB_HOST=localhost
export DB_USER=bouncer_ro
export DB_PASSWORD=your_password
export DB_NAME=gaia

# Run the server
mix run --no-halt
```

## Configuration

Bouncer is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BOUNCER_PORT` | HTTP server port | 4444 |
| `DB_HOST` | PostgreSQL hostname | localhost |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_NAME` | Database name | gaia |
| `DB_USER` | Database username | bouncer_ro |
| `DB_PASSWORD` | Database password | (required) |
| `DB_POOL_SIZE` | Connection pool size | 10 |

See `.env.example` for a complete configuration template.

## API

### Health Check
```bash
curl http://localhost:4444/health
```

### Certificate Validation
```bash
curl -X POST http://localhost:4444/validate \
  -H "X-Client-Cert: $(cat certificate.pem)"
```

**Response Codes:**
- `200` - Certificate is valid
- `412` - Certificate is revoked or unknown
- `404` - Invalid endpoint

## Development

```bash
# Run tests
mix test

# Run CI suite (tests, linting, formatting)
mix ci

# Format code
mix format

# Run linting
mix credo
```

## Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment, scaling, and operations
- **[Contributing Guidelines](AGENTS.md)** - Best practices for developers and AI agents

## Architecture

Bouncer uses:
- **Plug/Bandit** for HTTP handling
- **Postgrex** for PostgreSQL connectivity with connection pooling
- **Telemetry** for request metrics and monitoring
- **X509** library for certificate parsing

The server operates with a read-only database user that can only SELECT from the `certificate_status` table, ensuring minimal security exposure.

## License

See [LICENSE](../LICENSE) file for details.
