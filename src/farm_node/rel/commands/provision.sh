#!/bin/sh
# Farm Node Provisioning Script
# This script runs in the context of a release and invokes the Provisioning.CLI module

set -e

# Determine the script's directory and release root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to display usage
usage() {
    cat << EOF
Farm Node Provisioning

USAGE:
    bin/farm_node provision [OPTIONS]

OPTIONS:
    Interactive mode (default):
        No options required. The script will prompt for all values.

    Non-interactive mode:
        --hub-address URL          Hub server URL (e.g., https://hub.gaia.coop)
        --provisioning-key KEY     One-time provisioning key
        --farm-identifier ID       Unique farm identifier (lowercase, hyphens)
        --yes                      Skip confirmation prompt

EXAMPLES:
    # Interactive mode
    bin/farm_node provision

    # Non-interactive mode
    bin/farm_node provision \\
        --hub-address https://hub.gaia.coop \\
        --provisioning-key SECRET123 \\
        --farm-identifier green-acres \\
        --yes

NOTES:
    - This command must be run before the first start of the Farm Node
    - mTLS credentials will be stored in priv/ssl/
    - The node must be restarted after provisioning

EOF
    exit 0
}

# Parse command-line arguments
HUB_ADDRESS=""
PROVISIONING_KEY=""
FARM_IDENTIFIER=""
SKIP_CONFIRMATION="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            ;;
        --hub-address)
            HUB_ADDRESS="$2"
            shift 2
            ;;
        --provisioning-key)
            PROVISIONING_KEY="$2"
            shift 2
            ;;
        --farm-identifier)
            FARM_IDENTIFIER="$2"
            shift 2
            ;;
        --yes|-y)
            SKIP_CONFIRMATION="true"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build the Elixir command based on whether we have arguments
if [ -n "$HUB_ADDRESS" ] && [ -n "$PROVISIONING_KEY" ] && [ -n "$FARM_IDENTIFIER" ]; then
    # Non-interactive mode
    ELIXIR_CMD="Gaia.FarmNode.HubConnection.Provisioning.CLI.run([
      hub_address: \"$HUB_ADDRESS\",
      provisioning_key: \"$PROVISIONING_KEY\",
      farm_identifier: \"$FARM_IDENTIFIER\",
      skip_confirmation: $SKIP_CONFIRMATION
    ])"
else
    # Interactive mode
    if [ -n "$HUB_ADDRESS" ] || [ -n "$PROVISIONING_KEY" ] || [ -n "$FARM_IDENTIFIER" ]; then
        echo "Error: All three options must be provided for non-interactive mode"
        echo "Required: --hub-address, --provisioning-key, --farm-identifier"
        echo ""
        echo "Use --help for usage information"
        exit 1
    fi

    ELIXIR_CMD="Gaia.FarmNode.HubConnection.Provisioning.CLI.run_interactive()"
fi

# Execute the provisioning via RPC
exec "$RELEASE_ROOT/bin/farm_node" rpc "$ELIXIR_CMD"
