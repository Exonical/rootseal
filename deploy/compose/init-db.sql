-- Initialize rootseal database schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Agents table
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    serial VARCHAR(255),
    labels JSONB,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(hostname, serial)
);

-- Volumes table
CREATE TABLE volumes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id),
    device_path VARCHAR(255) NOT NULL,
    uuid VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(agent_id, device_path)
);

-- Key versions table
CREATE TABLE key_versions (
    id SERIAL PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id),
    version INTEGER NOT NULL,
    vault_key_id VARCHAR(255) NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(volume_id, version)
);

-- TPM enrollment table for attestation
CREATE TABLE tpm_enrollments (
    id SERIAL PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) UNIQUE,
    ek_public BYTEA,
    ek_cert BYTEA,
    ak_public BYTEA NOT NULL,
    ak_name BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Nonces table for replay protection
CREATE TABLE attestation_nonces (
    id SERIAL PRIMARY KEY,
    volume_uuid VARCHAR(255) NOT NULL,
    nonce BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_agents_hostname ON agents(hostname);
CREATE INDEX idx_volumes_agent_id ON volumes(agent_id);
CREATE INDEX idx_volumes_uuid ON volumes(uuid);
CREATE INDEX idx_key_versions_volume_id ON key_versions(volume_id);
CREATE INDEX idx_key_versions_version ON key_versions(volume_id, version);
CREATE INDEX idx_tpm_enrollments_volume_id ON tpm_enrollments(volume_id);
CREATE INDEX idx_attestation_nonces_volume_uuid ON attestation_nonces(volume_uuid);
CREATE INDEX idx_attestation_nonces_expires ON attestation_nonces(expires_at);
