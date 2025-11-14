# Bouncer Quick Start Guide

Get the Bouncer OCSP server running in under 5 minutes.

## Prerequisites

- Docker and Docker Compose installed

## Quick Start with Docker Compose

This is the fastest way to get Bouncer running with a PostgreSQL database.

### 1. Clone and Navigate

```bash
cd gaia/bouncer
```

### 2. Start Services

```bash
docker-compose up -d
```

This starts:
- PostgreSQL database on port 5432
- Bouncer server on port 4444

### 3. Verify It's Running

```bash
# Health check
curl http://localhost:4444/health

# Expected output: OK
```

### 4. Test Certificate Validation

Create a test certificate:

```bash
# Generate a test certificate
openssl req -x509 -newkey rsa:2048 -keyout test.key -out test.crt \
  -days 365 -nodes -subj "/CN=Test Certificate"

# Test the validate endpoint
curl -X POST http://localhost:4444/validate \
  -H "X-Client-Cert: $(cat test.crt)"

# Expected: 412 (certificate not in database)
```

### 5. Add Test Data

```bash
# Connect to the database
docker-compose exec postgres psql -U postgres -d gaia

# Insert a test certificate status
INSERT INTO certificate_status (user_uuid, certificate_serial, status)
VALUES ('550e8400-e29b-41d4-a716-446655440000', 123456789, 'valid');

# Exit
\q
```

### 6. View Logs

```bash
# Follow Bouncer logs
docker-compose logs -f bouncer

# You'll see telemetry events for each request
```

## Quick Start without Docker

If you have Elixir installed locally:

### 1. Set Environment Variables

```bash
export BOUNCER_PORT=4444
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=gaia
export DB_USER=bouncer_ro
export DB_PASSWORD=your_password
```

### 2. Install Dependencies

```bash
cd bouncer
mix deps.get
```

### 3. Start the Server

```bash
mix run --no-halt
```

## Next Steps

- Read [README.md](README.md) for architecture details
- See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment
- Configure reverse proxy integration (Nginx/Apache)
- Set up monitoring and alerting

## Common Issues

### Port Already in Use

```bash
# Change the port
export BOUNCER_PORT=4445
docker-compose down && docker-compose up -d
```

### Database Connection Failed

```bash
# Check if PostgreSQL is running
docker-compose ps

# View database logs
docker-compose logs postgres
```

### Dependencies Not Found (Native)

```bash
# Make sure Elixir and Erlang are installed
elixir --version

# Install or update dependencies
mix deps.get
mix deps.update --all
```

## Stop Services

```bash
# Stop but keep data
docker-compose stop

# Stop and remove containers (keeps volumes)
docker-compose down

# Stop and remove everything including data
docker-compose down -v
```
