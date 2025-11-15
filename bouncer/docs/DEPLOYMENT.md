# Bouncer Deployment Guide

This guide covers deployment options for the Bouncer OCSP server.

## Quick Links

- **Docker Deployment**: See [`../deployment/docker/`](../deployment/docker/README.md)
- **Kubernetes Deployment**: See [`../deployment/kubernetes/`](../deployment/kubernetes/README.md)
- **Deployment Files**: All deployment configurations in [`../deployment/`](../deployment/)

## Prerequisites

- PostgreSQL 14+ database
- Elixir 1.19+ / Erlang 28+ (for native deployment)
- Docker and Docker Compose (for containerized deployment)
- Kubernetes cluster v1.24+ (for Kubernetes deployment)

## Database Setup

### 1. Create Database and Schema

```sql
-- Connect as superuser
psql -U postgres

-- Create database (if not exists)
CREATE DATABASE gaia;

-- Connect to the database
\c gaia

-- Run the migration
\i priv/migrations/001_create_certificate_status.sql
```

### 2. Create Read-Only User

```sql
-- Create the bouncer_ro user
CREATE USER bouncer_ro WITH PASSWORD 'your_secure_password';

-- Grant minimal permissions
GRANT CONNECT ON DATABASE gaia TO bouncer_ro;
GRANT USAGE ON SCHEMA public TO bouncer_ro;
GRANT SELECT ON certificate_status TO bouncer_ro;
```

### 3. Verify Permissions

```bash
# Test connection
PGPASSWORD=your_secure_password psql -h localhost -U bouncer_ro -d gaia -c "SELECT COUNT(*) FROM certificate_status;"
```

## Deployment Options

### Option 1: Native Deployment

#### Development Mode

```bash
# Set environment variables
export BOUNCER_PORT=4444
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=gaia
export DB_USER=bouncer_ro
export DB_PASSWORD=your_secure_password
export DB_POOL_SIZE=10

# Install dependencies
cd bouncer
mix deps.get

# Run the server
mix run --no-halt
```

#### Production Mode

```bash
# Set environment to production
export MIX_ENV=prod

# Install production dependencies
mix deps.get --only prod

# Compile
mix compile

# Run the server
mix run --no-halt
```

### Option 2: Docker Deployment

**For detailed Docker deployment instructions, see [`../deployment/docker/README.md`](../deployment/docker/README.md)**

#### Using Docker Compose (Recommended for Testing)

```bash
# Navigate to deployment directory
cd deployment/docker

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Start all services (Bouncer + PostgreSQL)
docker-compose up -d

# View logs
docker-compose logs -f bouncer

# Stop services
docker-compose down
```

#### Using Docker (Production)

```bash
# Build the image from deployment directory
cd deployment/docker
docker build -t bouncer:latest -f Dockerfile ../..

# Run the container
docker run -d \
  --name bouncer \
  -p 4444:4444 \
  -e BOUNCER_PORT=4444 \
  -e DB_HOST=your-db-host \
  -e DB_PORT=5432 \
  -e DB_NAME=gaia \
  -e DB_USER=bouncer_ro \
  -e DB_PASSWORD=your_secure_password \
  -e DB_POOL_SIZE=10 \
  bouncer:latest

# Check logs
docker logs -f bouncer
```

### Option 3: Kubernetes Deployment

**For detailed Kubernetes deployment instructions, see [`../deployment/kubernetes/README.md`](../deployment/kubernetes/README.md)**

Kubernetes deployment provides high availability, auto-scaling, and zero-downtime updates.

#### Quick Deploy

```bash
# Navigate to Kubernetes manifests
cd deployment/kubernetes

# Update secret.yaml with your database password
# Update configmap.yaml with your database host

# Deploy all resources
kubectl apply -k .

# Check status
kubectl get pods -n bouncer
kubectl get svc -n bouncer

# View logs
kubectl logs -n bouncer -l app=bouncer --tail=100 -f
```

#### Features

- **High Availability**: 3+ replicas with automatic failover
- **Auto-scaling**: HorizontalPodAutoscaler based on CPU/memory
- **Health Checks**: Liveness and readiness probes
- **Rolling Updates**: Zero-downtime deployments
- **Resource Management**: CPU and memory limits/requests

### Option 4: Systemd Service (Linux)

Create a systemd service file at `/etc/systemd/system/bouncer.service`:

```ini
[Unit]
Description=Bouncer OCSP Server
After=network.target postgresql.service

[Service]
Type=simple
User=bouncer
WorkingDirectory=/opt/bouncer
Environment="MIX_ENV=prod"
Environment="BOUNCER_PORT=4444"
Environment="DB_HOST=localhost"
Environment="DB_PORT=5432"
Environment="DB_NAME=gaia"
Environment="DB_USER=bouncer_ro"
Environment="DB_PASSWORD=your_secure_password"
Environment="DB_POOL_SIZE=10"
ExecStart=/opt/bouncer/_build/prod/rel/bouncer/bin/bouncer start
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable bouncer

# Start service
sudo systemctl start bouncer

# Check status
sudo systemctl status bouncer

# View logs
sudo journalctl -u bouncer -f
```

## Reverse Proxy Configuration

### Nginx

```nginx
# Certificate validation endpoint
location /validate {
    # Extract client certificate
    proxy_set_header X-Client-Cert $ssl_client_cert;
    
    # Forward to Bouncer
    proxy_pass http://bouncer:4444/validate;
    proxy_method POST;
    
    # Handle response
    proxy_intercept_errors on;
    error_page 412 = @denied;
}

location @denied {
    return 403 "Certificate validation failed";
}
```

### Apache (mod_proxy)

```apache
<Location /validate>
    # Extract client certificate
    RequestHeader set X-Client-Cert "%{SSL_CLIENT_CERT}e"
    
    # Forward to Bouncer
    ProxyPass http://bouncer:4444/validate
    ProxyPassReverse http://bouncer:4444/validate
</Location>
```

## Monitoring

### Health Checks

```bash
# Simple health check
curl http://localhost:4444/health

# Expected output: "OK" with status 200
```

### Prometheus Metrics (Optional)

Add `telemetry_metrics_prometheus` to dependencies and configure:

```elixir
# In mix.exs
{:telemetry_metrics_prometheus, "~> 1.1"}

# Create lib/bouncer/telemetry/metrics.ex
defmodule Gaia.Bouncer.Telemetry.Metrics do
  use Prometheus.PlugExporter

  def metrics do
    [
      # Request duration histogram
      histogram(
        "bouncer_request_duration_milliseconds",
        event_name: [:bouncer, :request, :success],
        measurement: :duration,
        unit: {:native, :millisecond},
        description: "Request processing time"
      ),
      
      # Request counter
      counter(
        "bouncer_requests_total",
        event_name: [:bouncer, :request, :success],
        description: "Total number of requests"
      ),
      
      # Failure counter
      counter(
        "bouncer_failures_total",
        event_name: [:bouncer, :request, :failure],
        description: "Total number of failed requests"
      )
    ]
  end
end
```

## Performance Tuning

### Database Connection Pool

Adjust based on expected load:

```bash
# For high traffic (1000+ req/s)
export DB_POOL_SIZE=50

# For low traffic (< 100 req/s)
export DB_POOL_SIZE=10
```

### BEAM VM Tuning

```bash
# Increase number of schedulers
export ERL_MAX_PORTS=65536
export ERL_SCHEDULERS=8

# Increase atom limit
export ERL_OPTS="+A 128"
```

### HTTP Server Tuning

In `lib/bouncer/application.ex`:

```elixir
defp bandit_options do
  [
    port: port(),
    http_1_options: [
      max_requests: :infinity,
      max_request_line_length: 10_000,
      max_header_length: 10_000
    ],
    http_2_options: [
      max_concurrent_streams: 100
    ]
  ]
end
```

## Security Hardening

### 1. Network Security

- Deploy behind a firewall
- Restrict access to authorized reverse proxies only
- Use internal networks when possible

### 2. Database Security

- Verify read-only permissions
- Use SSL for database connections
- Rotate credentials regularly

### 3. Application Security

- Keep dependencies updated: `mix deps.update --all`
- Run security audits: `mix deps.audit`
- Monitor logs for suspicious activity

## Troubleshooting

### Connection Refused

```bash
# Check if service is running
systemctl status bouncer  # or docker ps

# Check port binding
netstat -tuln | grep 4444

# Check firewall
sudo ufw status
```

### Database Connection Errors

```bash
# Test database connectivity
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME

# Check database logs
sudo journalctl -u postgresql -f
```

### High Latency

- Check database query performance
- Monitor connection pool utilization
- Review telemetry logs for slow queries
- Consider adding database indexes

## Scaling

### Horizontal Scaling

Deploy multiple Bouncer instances behind a load balancer:

```nginx
upstream bouncer_backend {
    least_conn;
    server bouncer1:4444;
    server bouncer2:4444;
    server bouncer3:4444;
}

server {
    location /validate {
        proxy_pass http://bouncer_backend;
    }
}
```

### Database Scaling

- Add read replicas for high read load
- Implement connection pooling (PgBouncer)
- Partition certificate_status table if needed

## Backup and Recovery

### Database Backups

```bash
# Backup certificate_status table
pg_dump -U postgres -d gaia -t certificate_status > certificate_status_backup.sql

# Restore
psql -U postgres -d gaia < certificate_status_backup.sql
```

### Application State

Bouncer is stateless - no application-level backups needed.

## Updates and Maintenance

### Rolling Updates

```bash
# 1. Deploy new version to standby instance
# 2. Run health checks
# 3. Switch traffic to new instance
# 4. Update remaining instances
# 5. Verify all instances are healthy
```

### Zero-Downtime Updates

- Use blue-green deployment
- Update one instance at a time
- Monitor error rates during rollout
- Keep rollback plan ready
