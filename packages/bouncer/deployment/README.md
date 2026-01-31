# Bouncer Deployment

This directory contains deployment configurations for the Bouncer OCSP server.

## Deployment Options

### Docker
- **Location**: `docker/`
- **Files**: Dockerfile, docker-compose.yml, .env.example
- **Best for**: Local development, testing, small deployments
- **Documentation**: See [Docker README](docker/README.md)

### Kubernetes
- **Location**: `kubernetes/`
- **Files**: Complete Kubernetes manifests (Deployment, Service, HPA, etc.)
- **Best for**: Production deployments, high availability, auto-scaling
- **Documentation**: See [Kubernetes README](kubernetes/README.md)

## Quick Start

### Docker Compose (Easiest)
```bash
cd docker
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

### Kubernetes (Production)
```bash
cd kubernetes
# Edit secret.yaml and configmap.yaml with your configuration
kubectl apply -k .
```

## Prerequisites

- PostgreSQL 14+ database
- For Docker: Docker and Docker Compose
- For Kubernetes: Kubernetes cluster (v1.24+) and kubectl

## Database Setup

Before deploying, ensure your PostgreSQL database is set up:

1. Create the database and run migrations (see `../priv/migrations/`)
2. Create the read-only user `bouncer_ro`
3. Grant SELECT permissions on `certificate_status` table

See the main [DEPLOYMENT.md](../docs/DEPLOYMENT.md) for detailed database setup instructions.

## Architecture

Bouncer is designed to be:
- **Stateless**: No local state, all data in PostgreSQL
- **Horizontally scalable**: Deploy multiple instances behind a load balancer
- **High availability**: Automatic health checks and rolling updates
- **Lightweight**: Minimal resource footprint (~128MB RAM, 100m CPU per instance)

## Security Considerations

- Use strong passwords for database connections
- Store secrets securely (Kubernetes Secrets, Sealed Secrets, or external secret managers)
- Run behind a reverse proxy with TLS termination
- Restrict network access to Bouncer endpoints
- Use read-only database user with minimal permissions

## Monitoring

Bouncer emits telemetry events that can be consumed by monitoring systems:
- Request success/failure counts
- Request duration metrics
- Health check endpoint at `/health`

Configure your monitoring stack to scrape these metrics for visibility into performance and reliability.
