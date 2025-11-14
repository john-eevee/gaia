-- Create the certificate_status table
CREATE TABLE IF NOT EXISTS certificate_status (
    user_uuid UUID NOT NULL,
    certificate_serial BIGINT PRIMARY KEY,
    status VARCHAR(20) NOT NULL CHECK (status IN ('valid', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_certificate_status_user_uuid ON certificate_status(user_uuid);
CREATE INDEX IF NOT EXISTS idx_certificate_status_status ON certificate_status(status);

-- Create a read-only user for the bouncer service
-- Note: This should be run separately with appropriate credentials
-- DO $$
-- BEGIN
--   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'bouncer_ro') THEN
--     CREATE USER bouncer_ro WITH PASSWORD 'change_this_password';
--   END IF;
-- END
-- $$;

-- Grant minimal permissions to the read-only user
-- GRANT CONNECT ON DATABASE gaia TO bouncer_ro;
-- GRANT USAGE ON SCHEMA public TO bouncer_ro;
-- GRANT SELECT ON certificate_status TO bouncer_ro;
