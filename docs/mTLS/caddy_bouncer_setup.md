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

The Hub sits behind Caddy. Since Caddy handles the mTLS and Bouncer check, the Hub can trust the requests. However, it often needs to know *who* the client is.

### 1. Extracting Client Information in Phoenix

You can create a custom Plug to extract the client certificate or subject forwarded by Caddy.

```elixir
defmodule Gaia.HubWeb.Plugs.MTLSAuth do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    # Caddy can be configured to pass the certificate subject or other details
    case get_req_header(conn, "x-client-subject") do
      [subject | _] ->
        assign(conn, :current_client_subject, subject)
      [] ->
        # Optional: Handle missing auth if Caddy didn't reject it
        conn
    end
  end
end
```

### 2. Caddyfile Update to Pass Subject

Update your `Caddyfile` to pass the subject to the Hub:

```caddy
    reverse_proxy hub:4000 {
        header_up X-Client-Subject {http.request.tls.client.subject}
    }
```

## Integration Testing

To test the full flow:
1. Start the services using the provided `docker-compose.yml` in `src/testing_facility/caddy/`.
2. Generate a client certificate signed by the same CA.
3. Attempt to connect to Caddy using the client certificate:
   `curl -v --cert client.pem --key client.key https://localhost:8443/`
4. Verify that Bouncer receives the validation request and the Hub receives the proxied request.
