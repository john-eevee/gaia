# Caddy mTLS with Bouncer (OCSP-like Check)

This document describes how to configure Caddy to perform mTLS verification and validate the client certificate against the Bouncer service (OCSP-like check).

## Overview

1. **Caddy** terminates TLS and requires a client certificate.
2. **Caddy** extracts the client certificate.
3. **Caddy** sends a sub-request to **Bouncer** (`/validate`) with the certificate.
4. If **Bouncer** returns `200 OK`, Caddy forwards the request to the **Hub** (Phoenix).
5. If **Bouncer** returns `412 Precondition Failed`, Caddy rejects the request.

## Caddy Configuration (Caddyfile)

```caddy
{
    debug
}

# The public entry point
:443 {
    tls {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /path/to/ca.pem
        }
    }

    # Use forward_auth to validate the certificate with Bouncer
    forward_auth bouncer:4444 {
        uri /validate
        header_up X-Client-Cert {http.request.tls.client.certificate_pem}
    }

    # If bouncer passes, proxy to the Hub
    reverse_proxy hub:4000
}
```

## Bouncer Integration

Bouncer expects the PEM-encoded certificate in the `X-Client-Cert` header. It parses the serial number and checks it against the `certificate_status` table in the database.

### Success (Valid Certificate)
- Bouncer returns `200 OK`.
- Caddy continues processing and proxies to Hub.

### Failure (Revoked or Unknown)
- Bouncer returns `412 Precondition Failed`.
- Caddy terminates the request and returns the failure to the client.

## Phoenix (Hub) Configuration

The Hub sits behind Caddy. It can trust that any request reaching it has already passed:
1. Standard TLS handshake (Valid signature, not expired).
2. mTLS verification (Signed by trusted CA).
3. Bouncer check (Not revoked in the database).

To identify the user/farmer, the Hub can look at the forwarded headers if Caddy is configured to pass them (e.g., `X-Client-Subject`).
