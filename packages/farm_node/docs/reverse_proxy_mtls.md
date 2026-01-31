To configure a reverse proxy to query a certificate validation server for mTLS, the most robust and common approach is using **Nginx** with the `auth_request` module. This allows the proxy to intercept the request after the SSL handshake, extract the client certificate details, and forward them to an external service (the "validation server") for a final "Allow/Deny" decision.

In the Gaia architecture, this is how the **Hub** typically ensures a **Farm Node's** certificate hasn't been revoked or blacklisted in the cooperative's database.

### 1. Nginx Configuration

This configuration assumes Nginx is acting as the entry point for the Hub or a Farm Node.

```nginx/etc/nginx/sites-available/gaia-hub.conf#L1-45
upstream gaia_backend {
    server 127.0.0.1:4000;
}

upstream cert_validator {
    server 127.0.0.1:8080; # The external validation service
}

server {
    listen 443 ssl;
    server_name hub.gaia.coop;

    # Server Certificates
    ssl_certificate /etc/nginx/certs/hub.gaia.coop.crt;
    ssl_certificate_key /etc/nginx/certs/hub.gaia.coop.key;

    # mTLS Configuration
    ssl_client_certificate /etc/nginx/certs/gaia-ca.crt; # The CA that signs Node certs
    ssl_verify_client on; # Set to 'on' to require a valid cert signed by the CA above
    ssl_verify_depth 2;

    location / {
        # Trigger the external validation check
        auth_request /validate-client-cert;

        proxy_pass http://gaia_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Pass verified DN to the backend application
        proxy_set_header X-Client-DN $ssl_client_s_dn;
    }

    # Internal location for the validation service
    location = /validate-client-cert {
        internal;
        proxy_pass http://cert_validator/v1/validate;

        # Send certificate metadata to the validator
        proxy_set_header X-Client-Cert-Serial $ssl_client_serial;
        proxy_set_header X-Client-Cert-DN     $ssl_client_s_dn;
        proxy_set_header X-Client-Cert-Verify $ssl_client_verify; # 'SUCCESS', 'FAILED', etc.

        # Optional: Send the full PEM certificate if the validator needs to parse it
        # proxy_set_header X-Client-Cert-Raw    $ssl_client_raw_cert;

        # Disable body for the sub-request
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }

    # Handle validation failures
    error_page 403 = /error-revoked;
    location /error-revoked {
        return 403 "Forbidden: Certificate Revoked or Invalid";
    }
}
```

### 2. How it Works

1.  **SSL Handshake**: Nginx performs the standard mTLS handshake using `ssl_client_certificate`. If the certificate is not signed by the specified CA, Nginx rejects it immediately.
2.  **`auth_request`**: Once the handshake is successful, Nginx pauses the request and makes an internal sub-request to `/validate-client-cert`.
3.  **Validation Server**: Your external service (e.g., a Go or Elixir microservice) receives the headers (Serial, DN). It checks these against a revocation database or a list of active Farm Nodes.
    - **Return `200 OK`**: Nginx proceeds to `proxy_pass` the original request to the backend.
    - **Return `401/403`**: Nginx aborts the request and returns the error to the client.
4.  **Backend Trust**: The backend application receives the `X-Client-DN` header, which it can trust because it is only set by Nginx after successful validation.

### 3. Implementation in the Gaia Context

In `farm_node/AGENTS.md`, Rule 2 states:

> If the Hub responds `403 Forbidden` (Certificate Revoked), the Node MUST immediately cease all data transmission and alert the local user.

By using the `auth_request` pattern on the Hub, you can instantly revoke a Node's access by updating the validation server's database, causing the proxy to return `403` for every subsequent heartbeat or telemetry upload.

### Alternatives

- **HAProxy**: Use `http-request lua` to call an external script or service during the request phase.
- **Traefik**: Use the [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) middleware, which functions similarly to Nginx's `auth_request`.
- **Envoy**: Use the [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) filter.
