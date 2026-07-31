package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

const assetSchema = `
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS host_groups (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    parent_id VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hosts (
    id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip VARCHAR(45),
    mac VARCHAR(17),
    os VARCHAR(64) DEFAULT 'unknown',
    os_version VARCHAR(64),
    arch VARCHAR(32),
    agent_version VARCHAR(32),
    agent_id VARCHAR(64),
    status VARCHAR(16) DEFAULT 'offline',
    risk_level VARCHAR(16) DEFAULT 'low',
    last_heartbeat TIMESTAMP,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    cpu VARCHAR(255),
    memory_mb BIGINT,
    disk_gb BIGINT,
    cloud_instance_id VARCHAR(128),
    tags TEXT[],
    group_id VARCHAR(64) REFERENCES host_groups(id),
    department VARCHAR(128),
    owner VARCHAR(128),
    importance VARCHAR(16) DEFAULT 'medium',
    alert_count INT DEFAULT 0,
    vuln_count INT DEFAULT 0,
    rasp_blocked INT DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_risk_level ON hosts(risk_level);
CREATE INDEX IF NOT EXISTS idx_hosts_os ON hosts(os);
CREATE INDEX IF NOT EXISTS idx_hosts_group_id ON hosts(group_id);
CREATE INDEX IF NOT EXISTS idx_hosts_last_heartbeat ON hosts(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_hosts_tags ON hosts USING GIN(tags);

CREATE TABLE IF NOT EXISTS host_network_interfaces (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    mac VARCHAR(17),
    ip VARCHAR(45),
    netmask VARCHAR(32),
    gateway VARCHAR(45),
    dns VARCHAR(255),
    state VARCHAR(16) DEFAULT 'up',
    scanned_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, name)
);

CREATE TABLE IF NOT EXISTS host_ports (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    port INT NOT NULL,
    protocol VARCHAR(8) DEFAULT 'tcp',
    state VARCHAR(16) DEFAULT 'open',
    service VARCHAR(64),
    banner TEXT,
    pid INT,
    process_name VARCHAR(255),
    scanned_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_host_ports_host_id ON host_ports(host_id);
CREATE INDEX IF NOT EXISTS idx_host_ports_port ON host_ports(port);

CREATE TABLE IF NOT EXISTS host_processes (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    pid INT NOT NULL,
    ppid INT,
    name VARCHAR(255) NOT NULL,
    path TEXT,
    proc_user VARCHAR(64),
    cmdline TEXT,
    cpu_percent DECIMAL(10,2),
    memory_mb BIGINT,
    started_at TIMESTAMP,
    scanned_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, pid)
);

CREATE INDEX IF NOT EXISTS idx_host_processes_host_id ON host_processes(host_id);
CREATE INDEX IF NOT EXISTS idx_host_processes_name ON host_processes(name);

CREATE TABLE IF NOT EXISTS host_software (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(64),
    vendor VARCHAR(255),
    install_date DATE,
    scanned_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_host_software_host_id ON host_software(host_id);
CREATE INDEX IF NOT EXISTS idx_host_software_name ON host_software(name);

CREATE TABLE IF NOT EXISTS host_tags (
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (host_id, tag)
);

CREATE TABLE IF NOT EXISTS host_change_history (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    change_type VARCHAR(32) NOT NULL,
    field_name VARCHAR(64),
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR(128),
    changed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_host_change_history_host_id ON host_change_history(host_id);
CREATE INDEX IF NOT EXISTS idx_host_change_history_changed_at ON host_change_history(changed_at);

CREATE TABLE IF NOT EXISTS host_containers (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    container_id VARCHAR(64) NOT NULL,
    name VARCHAR(255),
    image VARCHAR(255),
    status VARCHAR(32),
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    scanned_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, container_id)
);

CREATE INDEX IF NOT EXISTS idx_host_containers_host_id ON host_containers(host_id);

CREATE TABLE IF NOT EXISTS host_performance (
    id SERIAL PRIMARY KEY,
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    cpu_percent DECIMAL(10,2),
    memory_percent DECIMAL(10,2),
    memory_used_mb BIGINT,
    disk_percent DECIMAL(10,2),
    disk_used_gb BIGINT,
    network_in_bytes BIGINT,
    network_out_bytes BIGINT,
    load_avg_1 DECIMAL(10,2),
    load_avg_5 DECIMAL(10,2),
    load_avg_15 DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, timestamp)
);

CREATE INDEX IF NOT EXISTS idx_host_performance_host_id ON host_performance(host_id);
CREATE INDEX IF NOT EXISTS idx_host_performance_timestamp ON host_performance(timestamp);
`

const rulePlatformSchema = `
CREATE TABLE IF NOT EXISTS rule_sources (
    id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(32) NOT NULL,
    origin VARCHAR(64) NOT NULL,
    license VARCHAR(128),
    url TEXT,
    bundled BOOLEAN DEFAULT FALSE,
    connector BOOLEAN DEFAULT FALSE,
    restricted BOOLEAN DEFAULT FALSE,
    updatable BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rule_source_versions (
    id BIGSERIAL PRIMARY KEY,
    source_id VARCHAR(128) REFERENCES rule_sources(id) ON DELETE CASCADE,
    version VARCHAR(128) NOT NULL,
    content_hash VARCHAR(128) NOT NULL,
    snapshot_path TEXT,
    sync_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    synced_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(source_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_source_versions_immutable ON rule_source_versions(source_id, version);

CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(160) PRIMARY KEY,
    source_id VARCHAR(128) REFERENCES rule_sources(id) ON DELETE SET NULL,
    category VARCHAR(32) NOT NULL,
    name VARCHAR(255) NOT NULL,
    support_level VARCHAR(32) NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    rule_json JSONB NOT NULL,
    dedup_key VARCHAR(256),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_category ON detection_rules(category);
CREATE INDEX IF NOT EXISTS idx_detection_rules_support ON detection_rules(support_level);
CREATE INDEX IF NOT EXISTS idx_detection_rules_dedup ON detection_rules(dedup_key);

CREATE TABLE IF NOT EXISTS rule_bundles (
    id BIGSERIAL PRIMARY KEY,
    version VARCHAR(128) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL,
    bundle_hash VARCHAR(128) NOT NULL,
    bundle_path TEXT,
    activated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rule_hot_reload_events (
    id BIGSERIAL PRIMARY KEY,
    bundle_version VARCHAR(128) NOT NULL,
    target VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
`

const xdrV2Schema = `
CREATE TABLE IF NOT EXISTS xdr_events_v2 (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    event_uid VARCHAR(128) NOT NULL,
    source_component VARCHAR(16) NOT NULL,
    agent_id VARCHAR(64),
    host_id VARCHAR(64),
    observed_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    event_type VARCHAR(64),
    raw_event JSONB DEFAULT '{}',
    normalized_src_ip VARCHAR(45),
    normalized_dst_ip VARCHAR(45),
    actor_identity VARCHAR(255),
    victim_asset VARCHAR(255),
    technique_id VARCHAR(32),
    tactic_id VARCHAR(32),
    stage_hint VARCHAR(32),
    stage_confidence DECIMAL(5,3),
    risk_score DECIMAL(6,2),
    confidence_score DECIMAL(6,2),
    score_detail JSONB DEFAULT '{}',
    evaluation_version VARCHAR(16) NOT NULL DEFAULT 'xdr-eval.v2',
    attack_mapping_version VARCHAR(16),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, event_uid),
    UNIQUE(event_uid)
);
CREATE INDEX IF NOT EXISTS idx_xdr_events_v2_tenant ON xdr_events_v2(tenant_id);
CREATE INDEX IF NOT EXISTS idx_xdr_events_v2_observed ON xdr_events_v2(observed_at);
CREATE INDEX IF NOT EXISTS idx_xdr_events_v2_host ON xdr_events_v2(host_id);
CREATE INDEX IF NOT EXISTS idx_xdr_events_v2_technique ON xdr_events_v2(technique_id);

CREATE TABLE IF NOT EXISTS threat_events (
    event_uid VARCHAR(160) PRIMARY KEY,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    source_engine VARCHAR(64),
    event_type VARCHAR(128),
    agent_id VARCHAR(128),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    message TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    raw_event JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_events_category_time ON threat_events(category, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_agent ON threat_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_src_ip ON threat_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_threat_events_dst_ip ON threat_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_threat_events_raw ON threat_events USING GIN(raw_event);

CREATE TABLE IF NOT EXISTS traffic_sessions (
    session_uid VARCHAR(160) PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(128),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    src_port INT,
    dst_port INT,
    protocol VARCHAR(16),
    raw_event JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_time ON traffic_sessions(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_agent ON traffic_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_src_ip ON traffic_sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_dst_ip ON traffic_sessions(dst_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_raw ON traffic_sessions USING GIN(raw_event);
CREATE INDEX IF NOT EXISTS idx_traffic_sessions_raw_text_trgm ON traffic_sessions USING GIN ((raw_event::text) gin_trgm_ops);

CREATE TABLE IF NOT EXISTS xdr_attack_transitions (
    id BIGSERIAL PRIMARY KEY,
    from_technique VARCHAR(32) NOT NULL,
    from_tactic VARCHAR(32),
    to_technique VARCHAR(32) NOT NULL,
    to_tactic VARCHAR(32),
    transition_class VARCHAR(16) NOT NULL DEFAULT 'allowed',
    penalty DECIMAL(4,2) DEFAULT 0,
    confidence_adjust DECIMAL(4,2) DEFAULT 0,
    attack_mapping_version VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(from_technique, to_technique, attack_mapping_version)
);
CREATE INDEX IF NOT EXISTS idx_xdr_transitions_from ON xdr_attack_transitions(from_technique);

CREATE TABLE IF NOT EXISTS xdr_trusted_proxies (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    cidr VARCHAR(45) NOT NULL,
    description VARCHAR(255),
    priority INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_xdr_proxies_tenant ON xdr_trusted_proxies(tenant_id);

CREATE TABLE IF NOT EXISTS xdr_enrichment_snapshots (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    event_uid VARCHAR(128) NOT NULL REFERENCES xdr_events_v2(event_uid) ON DELETE CASCADE,
    asset_importance VARCHAR(16),
    asset_risk_level VARCHAR(16),
    vuln_count INT,
    vuln_high_count INT,
    identity_privilege VARCHAR(32),
    agent_display_name VARCHAR(255),
    attribution_confidence DECIMAL(4,2),
    attribution_reason TEXT,
    enrichment_errors JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xdr_enrich_event ON xdr_enrichment_snapshots(event_uid);
`

func ensureRuntimeSchema(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return fmt.Errorf("db pool is nil")
	}
	if _, err := db.Exec(ctx, coreSchema); err != nil {
		return fmt.Errorf("apply core schema: %w", err)
	}
	if _, err := db.Exec(ctx, assetSchema); err != nil {
		return fmt.Errorf("apply asset schema: %w", err)
	}
	if _, err := db.Exec(ctx, rulePlatformSchema); err != nil {
		return fmt.Errorf("apply rule platform schema: %w", err)
	}
	if _, err := db.Exec(ctx, xdrV2Schema); err != nil {
		return fmt.Errorf("apply xdr v2 schema: %w", err)
	}
	return nil
}

func ensureRuntimeSchemaOrLog(ctx context.Context, db *pgxpool.Pool) {
	if err := ensureRuntimeSchema(ctx, db); err != nil {
		log.Printf("警告: 初始化资产表失败: %v", err)
		return
	}
	log.Println("资产表初始化成功")
}
