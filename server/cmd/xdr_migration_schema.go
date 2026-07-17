package main

const xdrMigrationSchema = `
CREATE TABLE IF NOT EXISTS xdr_graph_nodes_versioned (
    tenant_id VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL,
    node_uid VARCHAR(128) NOT NULL,
    event_uid VARCHAR(128) NOT NULL,
    asset_id VARCHAR(64), ip VARCHAR(45), hostname VARCHAR(255), identity VARCHAR(255),
    technique_id VARCHAR(32), tactic_id VARCHAR(32), created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, algorithm_version, node_uid)
);
CREATE TABLE IF NOT EXISTS xdr_graph_edges_versioned (
    tenant_id VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL,
    edge_uid VARCHAR(384) NOT NULL,
    from_node_uid VARCHAR(128) NOT NULL,
    to_node_uid VARCHAR(128) NOT NULL,
    edge_type VARCHAR(32) NOT NULL,
    strength DECIMAL(8,6) NOT NULL,
    evidence_event_uids JSONB NOT NULL DEFAULT '[]',
    temporal_proximity_secs INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, algorithm_version, edge_uid)
);
CREATE TABLE IF NOT EXISTS xdr_chain_hypotheses_versioned (
    tenant_id VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL,
    hypothesis_uid VARCHAR(128) NOT NULL,
    seed_node_uid VARCHAR(128) NOT NULL,
    path_node_uids JSONB NOT NULL DEFAULT '[]',
    chain_score DECIMAL(8,4) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    hypothesis_status VARCHAR(32) NOT NULL,
    evaluation_version VARCHAR(32) NOT NULL,
    path_evidence JSONB NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    traversal_depth INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, algorithm_version, hypothesis_uid)
);
CREATE TABLE IF NOT EXISTS xdr_algorithm_checkpoints (
    tenant_id VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL,
    input_checksum VARCHAR(64) NOT NULL,
    graph_checksum VARCHAR(64) NOT NULL,
    event_count INT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, algorithm_version)
);
CREATE TABLE IF NOT EXISTS xdr_input_quarantine (
    id BIGSERIAL PRIMARY KEY,
    algorithm_version VARCHAR(32) NOT NULL,
    schema_version VARCHAR(64),
    reason TEXT NOT NULL,
    source VARCHAR(64) NOT NULL,
    redacted_record JSONB NOT NULL,
    payload_sha256 VARCHAR(64) NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL,
    UNIQUE (algorithm_version, payload_sha256)
);
ALTER TABLE xdr_input_quarantine ADD COLUMN IF NOT EXISTS source VARCHAR(64) NOT NULL DEFAULT 'canonical';
ALTER TABLE xdr_input_quarantine ADD COLUMN IF NOT EXISTS redacted_record JSONB NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS xdr_scoring_input_details_versioned (
    tenant_id VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL CHECK (algorithm_version = 'v3-shadow'),
    feature_version VARCHAR(32) NOT NULL,
    input_checksum VARCHAR(64) NOT NULL,
    detail_uid VARCHAR(64) NOT NULL,
    detail_checksum VARCHAR(64) NOT NULL,
    detail JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, algorithm_version, feature_version, detail_uid),
    UNIQUE (tenant_id, algorithm_version, feature_version, input_checksum, detail_checksum)
);
CREATE OR REPLACE FUNCTION reject_xdr_scoring_detail_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'xdr scoring input details are immutable';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS xdr_scoring_input_details_immutable ON xdr_scoring_input_details_versioned;
CREATE TRIGGER xdr_scoring_input_details_immutable
BEFORE UPDATE OR DELETE ON xdr_scoring_input_details_versioned
FOR EACH ROW EXECUTE FUNCTION reject_xdr_scoring_detail_mutation();
`
