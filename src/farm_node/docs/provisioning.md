# Farm Node Provisioning

This document describes how to provision a Farm Node in both development and production environments.

## Development (Mix)

During development, use the Mix task:

```bash
# Interactive mode
mix farm_node.provision

# Non-interactive mode
mix farm_node.provision \
  --hub-address https://hub.gaia.coop \
  --provisioning-key SECRET123 \
  --farm-identifier green-acres
```

## Production (Release)

After building and deploying a release, use the bundled `provision` command:

### Building the Release

```bash
# Build the release tarball
mix release farm_node

# The release will be at _build/prod/farm_node-0.1.0.tar.gz
```

### Extracting and Running

```bash
# Extract the release
cd /opt/farm_node
tar -xzf farm_node-0.1.0.tar.gz

# Interactive provisioning
bin/farm_node provision

# Non-interactive provisioning
bin/farm_node provision \
  --hub-address https://hub.gaia.coop \
  --provisioning-key SECRET123 \
  --farm-identifier green-acres \
  --yes

# View help
bin/farm_node provision --help
```

### After Provisioning

Once provisioned, the mTLS credentials are stored in `priv/ssl/`. The Farm Node application must be started (or restarted) to use these credentials:

```bash
# Start the Farm Node daemon
bin/farm_node daemon

# Or start in foreground
bin/farm_node start
```

## Programmatic Access (Advanced)

You can also invoke the provisioning functions directly from an IEx console or via RPC:

```elixir
# From a remote console
bin/farm_node remote

# Then in IEx:
Gaia.FarmNode.HubConnection.Provisioning.CLI.run_interactive()

# Or non-interactive:
Gaia.FarmNode.HubConnection.Provisioning.CLI.run([
  hub_address: "https://hub.gaia.coop",
  provisioning_key: "SECRET123",
  farm_identifier: "green-acres",
  skip_confirmation: true
])
```

## Architecture

The provisioning system is designed to work in both Mix and Release environments:

- **`Gaia.FarmNode.HubConnection.Provisioning.CLI`**: Core provisioning logic that works in any environment
- **`Mix.Tasks.FarmNode.Provision`**: Mix task wrapper for development
- **`rel/commands/provision.sh`**: Shell script wrapper for production releases

This architecture ensures that:
1. ✅ Development experience is smooth (`mix farm_node.provision`)
2. ✅ Production releases have a simple CLI (`bin/farm_node provision`)
3. ✅ The core logic is shared and testable
4. ✅ Programmatic access is available for automation

## Security Notes

- The provisioning key is a **one-time secret** provided by the cooperative
- After successful provisioning, mTLS certificates are stored in `priv/ssl/`
- **Never** commit `priv/ssl/` to version control
- Ensure `priv/ssl/` has restricted permissions (700)
- Back up your credentials securely
- If credentials are compromised, revoke them via the Hub and re-provision

## Troubleshooting

### "Already provisioned" error

The node can only be provisioned once. To re-provision:

1. Revoke existing credentials via the Hub admin interface
2. Remove local credentials: `rm -rf priv/ssl/`
3. Run provisioning again

### Network connectivity issues

- Verify the Hub address is correct and accessible
- Check firewall rules allow HTTPS traffic
- Ensure DNS resolution works for the Hub domain

### Invalid provisioning key

- Verify you copied the full provisioning key
- Check the key hasn't expired
- Contact your cooperative administrator for a new key
