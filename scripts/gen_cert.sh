# This script generates a self-signed certificate for development purposes.
# It creates a private key and a certificate valid for 365 days.
echo "Generating self-signed certificate for development..."
mkdir -p apps/hub/priv/certs
echo "Cleaning up old certificates..."
rm -f apps/hub/priv/certs/ca.key apps/hub/priv/certs/ca.pem
# 1. Create the CA's private key
echo "Creating new CA key..."
openssl genpkey -algorithm RSA -out apps/hub/priv/certs/ca.key

# 2. Create the CA's self-signed root certificate (this is the public part)
# This file (ca.pem) is what you will use in your Elixir/Phoenix config
# for the `cacertfile` option to trust your clients.
echo 'Creating new self-signed CA certificate...'
openssl req -x509 -new -nodes -key apps/hub/priv/certs/ca.key -subj "//OU=Development" -sha256 -days 3650 -out apps/hub/priv/certs/ca.pem
echo "Self-signed certificate generation complete."
