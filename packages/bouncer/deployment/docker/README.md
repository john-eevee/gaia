# Docker Deployment

This directory contains Docker and Docker Compose configurations for Bouncer.

## Files

- **Dockerfile**: Multi-stage build for production-ready image
- **docker-compose.yml**: Complete stack with PostgreSQL for local development
- **.env.example**: Environment variable template

## Quick Start

### 1. Setup Environment

```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
BOUNCER_PORT=4444
DB_HOST=postgres
DB_PORT=5432
DB_NAME=gaia
DB_USER=bouncer_ro
DB_PASSWORD=your_secure_password
DB_POOL_SIZE=10
```

### 2. Start Services

```bash
docker-compose up -d
```

This starts:
- Bouncer server on port 4444
- PostgreSQL database on port 5432

### 3. Initialize Database

The database migrations are automatically run on first start. To manually set up the read-only user:

```bash
docker-compose exec postgres psql -U postgres -d gaia
```

Then run:
```sql
CREATE USER bouncer_ro WITH PASSWORD 'your_password';
GRANT CONNECT ON DATABASE gaia TO bouncer_ro;
GRANT USAGE ON SCHEMA public TO bouncer_ro;
GRANT SELECT ON certificate_status TO bouncer_ro;
```

### 4. Verify

```bash
# Check service health
curl http://localhost:4444/health

# View logs
docker-compose logs -f bouncer
```

## Building the Image

### Local Build

```bash
docker build -t bouncer:latest -f Dockerfile ..
```

Note: Build from the parent directory (bouncer/) to include all source code.

### Production Build

```bash
cd ..
docker build -t ghcr.io/john-eevee/gaia-bouncer:latest -f deployment/docker/Dockerfile .
docker push ghcr.io/john-eevee/gaia-bouncer:latest
```

## Docker Compose Services

### bouncer
- Builds from Dockerfile
- Exposes port 4444
- Auto-restarts on failure
- Health checks via `/health` endpoint

### postgres
- PostgreSQL 14 Alpine
- Persistent data volume
- Automatic database initialization
- Health checks via `pg_isready`

## Configuration

All configuration is via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| BOUNCER_PORT | HTTP server port | 4444 |
| DB_HOST | PostgreSQL hostname | postgres |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | gaia |
| DB_USER | Database username | bouncer_ro |
| DB_PASSWORD | Database password | (required) |
| DB_POOL_SIZE | Connection pool size | 10 |

## Volumes

- `postgres-data`: PostgreSQL data persistence

## Networks

- `bouncer-network`: Bridge network for service communication

## Production Deployment

For production, consider:

1. **External Database**: Use managed PostgreSQL instead of docker-compose database
2. **Secrets Management**: Use Docker secrets or external secret management
3. **Load Balancing**: Deploy multiple Bouncer containers behind a load balancer
4. **Monitoring**: Add Prometheus/Grafana for metrics
5. **Logging**: Configure centralized logging (ELK, Loki, etc.)

### Example with External Database

```yaml
services:
  bouncer:
    image: ghcr.io/john-eevee/gaia-bouncer:latest
    ports:
      - "4444:4444"
    environment:
      DB_HOST: your-rds-endpoint.amazonaws.com
      DB_PASSWORD: ${DB_PASSWORD}
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
```

## Troubleshooting

### Container Won't Start

Check logs:
```bash
docker-compose logs bouncer
```

### Database Connection Failed

Verify database is ready:
```bash
docker-compose exec postgres pg_isready
```

Test connection:
```bash
docker-compose exec postgres psql -U postgres -d gaia
```

### Health Check Failing

Check if service is responding:
```bash
docker-compose exec bouncer wget -O- http://localhost:4444/health
```

## Cleanup

Stop and remove containers:
```bash
docker-compose down
```

Remove volumes (deletes database):
```bash
docker-compose down -v
```
