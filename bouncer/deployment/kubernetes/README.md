# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Bouncer OCSP server.

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured to access your cluster
- PostgreSQL database accessible from the cluster
- Container image built and pushed to a registry

## Quick Start

### 1. Update Configuration

Edit `secret.yaml` to set your database password:
```yaml
stringData:
  DB_PASSWORD: "your_actual_secure_password"
```

Edit `configmap.yaml` to set your database host:
```yaml
data:
  DB_HOST: "your-postgres-host"
```

### 2. Deploy

Deploy all resources using kubectl:
```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f hpa.yaml
```

Or use kustomize:
```bash
kubectl apply -k .
```

### 3. Verify Deployment

Check pod status:
```bash
kubectl get pods -n bouncer
```

Check service:
```bash
kubectl get svc -n bouncer
```

View logs:
```bash
kubectl logs -n bouncer -l app=bouncer --tail=100 -f
```

## Manifests

### namespace.yaml
Creates the `bouncer` namespace for isolation.

### configmap.yaml
Non-sensitive configuration:
- Server port
- Database connection details (host, port, database name, user)
- Connection pool size

### secret.yaml
Sensitive data:
- Database password

**Security Note**: For production, use:
- [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
- [External Secrets Operator](https://external-secrets.io/)
- Cloud provider secret managers (AWS Secrets Manager, GCP Secret Manager, etc.)

### deployment.yaml
Defines the Bouncer application deployment:
- **Replicas**: 3 (can be scaled manually or via HPA)
- **Strategy**: RollingUpdate for zero-downtime deployments
- **Resources**: 
  - Requests: 128Mi memory, 100m CPU
  - Limits: 256Mi memory, 500m CPU
- **Health checks**:
  - Liveness probe on `/health`
  - Readiness probe on `/health`
- **Security**: Runs as non-root user with minimal capabilities

### service.yaml
ClusterIP service exposing Bouncer on port 4444.

### hpa.yaml
Horizontal Pod Autoscaler:
- Scales between 3-10 replicas based on CPU (70%) and memory (80%) utilization
- Smart scale-up/scale-down policies to prevent flapping

## Scaling

### Manual Scaling
```bash
kubectl scale deployment bouncer -n bouncer --replicas=5
```

### Autoscaling
The HPA automatically scales based on resource utilization. Monitor with:
```bash
kubectl get hpa -n bouncer
```

## Updating

### Update Configuration
```bash
kubectl edit configmap bouncer-config -n bouncer
kubectl rollout restart deployment bouncer -n bouncer
```

### Update Image
```bash
kubectl set image deployment/bouncer bouncer=ghcr.io/john-eevee/gaia-bouncer:v1.2.3 -n bouncer
```

Or edit the deployment:
```bash
kubectl edit deployment bouncer -n bouncer
```

### Monitor Rollout
```bash
kubectl rollout status deployment bouncer -n bouncer
kubectl rollout history deployment bouncer -n bouncer
```

## Ingress (Optional)

To expose Bouncer externally, create an Ingress resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bouncer-ingress
  namespace: bouncer
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: bouncer.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bouncer-service
            port:
              number: 4444
  tls:
  - hosts:
    - bouncer.example.com
    secretName: bouncer-tls
```

## Monitoring

### Prometheus ServiceMonitor

If using Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: bouncer
  namespace: bouncer
spec:
  selector:
    matchLabels:
      app: bouncer
  endpoints:
  - port: http
    interval: 30s
    path: /metrics
```

### View Metrics
```bash
kubectl port-forward -n bouncer svc/bouncer-service 4444:4444
curl http://localhost:4444/health
```

## Troubleshooting

### Check Events
```bash
kubectl get events -n bouncer --sort-by='.lastTimestamp'
```

### Pod Not Starting
```bash
kubectl describe pod <pod-name> -n bouncer
kubectl logs <pod-name> -n bouncer
```

### Database Connection Issues
```bash
# Test from within a pod
kubectl exec -it <pod-name> -n bouncer -- sh
# If shell is available, test connectivity
```

### Resource Issues
```bash
kubectl top pods -n bouncer
kubectl describe hpa bouncer-hpa -n bouncer
```

## Cleanup

Remove all resources:
```bash
kubectl delete namespace bouncer
```

Or remove individual resources:
```bash
kubectl delete -k .
```
