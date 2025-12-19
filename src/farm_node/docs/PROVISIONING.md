# Farm Node Provisioning

This document describes the First Boot provisioning sequence for the Gaia Farm Node.

## Overview

On the very first boot, a Farm Node has no identity. The provisioning workflow establishes a secure, authenticated connection with the Cooperative Hub using mutual TLS (mTLS) authentication.

## Architecture

The provisioning system is organized within the `HubConnection` bounded context:

```
lib/farm_node/hub_connection/
├── provisioning.ex                              # Main orchestrator
└── provisioning/
    ├── certificate_authority.ex                 # CSR generation & validation
    ├── client.ex                                # HTTP client for Hub API
    └── storage.ex                               # Secure credential storage
```

## Provisioning Flow

### 1. User Input

The farmer provides three pieces of information:

- **Hub Address**: The URL of the cooperative's Hub server (e.g., `https://hub.gaia.coop`)
- **Provisioning Key**: A one-time secret provided by the cooperative administrator
- **Farm Identifier**: A unique name for this farm node (e.g., `green-acres-farm`)

### 2. Local CSR Generation

The node generates:
- A 4096-bit RSA private key (for strong security)
- A Certificate Signing Request (CSR) containing:
  - Common Name: `farm-node-{identifier}`
  - Organization: `Gaia Cooperative Farm`
  - Country: `US`

### 3. Hub Authentication

The node sends an HTTPS POST request to the Hub's public provisioning endpoint:

```
POST /api/v1/provision
Content-Type: application/json

{
  "provisioning_key": "secret-key-123",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "farm_identifier": "green-acres",
  "node_version": "0.1.0"
}
```

### 4. Certificate Receipt

If the provisioning key is valid and the farm identifier is not already registered:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n..."
}
```

The Hub returns a signed X.509 certificate.

### 5. Secure Storage

The credentials are stored in `priv/ssl/` with restricted permissions:

```
priv/ssl/
├── farm_node_cert.pem     (mode 0644)
├── farm_node_key.pem      (mode 0600)
└── provisioning_state.json
```

**Security Note**: This directory is automatically excluded from version control via `.gitignore`.

### 6. State Transition

The node transitions from `unprovisioned` to `active` status.

## Usage

### Interactive Provisioning

```bash
mix farm_node.provision
```

This will prompt for:
1. Hub Address
2. Provisioning Key
3. Farm Identifier

### Non-Interactive Provisioning

```bash
mix farm_node.provision \
  --hub-address https://hub.gaia.coop \
  --provisioning-key SECRET123 \
  --farm-identifier green-acres
```

### Check Status

```bash
mix farm_node.status
```

## Error Handling

The provisioning workflow handles various error conditions:

| Error | Cause | Resolution |
|-------|-------|------------|
| `invalid_provisioning_key` | Key doesn't match Hub records | Contact cooperative administrator |
| `farm_already_provisioned` | Identifier already registered | Choose a different identifier |
| `already_provisioned` | Node has existing credentials | Revoke existing credentials first |
| `hub_request_failed` | Network or Hub unavailable | Check connectivity and Hub status |

## Security Considerations

### 1. Provisioning Key Protection

The provisioning key is a sensitive, one-time credential:
- Should be transmitted securely (encrypted communication)
- Should be revoked after use
- Never stored permanently on the node

### 2. Certificate Storage

Private keys are stored with restrictive permissions:
- Directory: `0700` (owner only)
- Private key: `0600` (owner read/write only)
- Certificate: `0644` (owner write, all read)

### 3. Certificate Revocation

If the Hub revokes a node's certificate:
- The node will receive a `403 Forbidden` during heartbeat
- All Hub communication ceases immediately
- Local operations continue (offline-first design)
- Local user is alerted

## Testing

Comprehensive tests cover:

- CSR generation and validation
- Certificate storage and retrieval
- Provisioning state management
- Error handling

Run tests:

```bash
mix test
```

## API Reference

### `Gaia.FarmNode.HubConnection.Provisioning`

Main provisioning orchestrator.

#### `provision(hub_address, provisioning_key, farm_identifier)`

Executes the complete provisioning workflow.

Returns:
- `:ok` on success
- `{:error, reason}` on failure

#### `provisioned?()`

Returns `true` if the node has valid credentials.

#### `status()`

Returns `:unprovisioned` or `:active`.

### `Gaia.FarmNode.HubConnection.Provisioning.Storage`

Secure credential storage.

#### `store_credentials(certificate_pem, private_key_pem)`

Stores mTLS credentials securely.

#### `load_credentials()`

Loads credentials from disk.

Returns `{:ok, %{cert: pem, key: pem}}` or `{:error, :not_provisioned}`.

#### `revoke_credentials()`

Removes stored credentials (for re-provisioning or security incidents).

### `Gaia.FarmNode.HubConnection.Provisioning.CertificateAuthority`

Certificate operations.

#### `generate_csr(farm_identifier)`

Generates a private key and CSR.

Returns `{:ok, %{csr: pem, private_key: pem}}`.

#### `validate_certificate(cert_pem)`

Validates a certificate PEM string.

## Future Enhancements

- [ ] Automatic certificate renewal before expiration
- [ ] Support for Hardware Security Modules (HSM)
- [ ] Certificate rotation without service interruption
- [ ] Backup and recovery procedures
- [ ] Multi-Hub federation support
