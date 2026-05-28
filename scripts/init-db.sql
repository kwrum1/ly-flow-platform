-- 流影安全态势感知平台 - PostgreSQL Schema
-- 版本: v2.0.0
-- 更新日期: 2026-05-08

-- 启用扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- 1. 事件表
-- =====================================================
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    source VARCHAR(64),
    severity VARCHAR(16),
    src_ip INET,
    dst_ip INET,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(16),
    domain VARCHAR(256),
    tags TEXT[],
    mitre_tactic VARCHAR(32),
    mitre_technique VARCHAR(32),
    raw_data JSONB,
    metadata JSONB,
    status VARCHAR(16) DEFAULT 'new',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_tags ON events USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);

-- =====================================================
-- 2. 资产表
-- =====================================================
CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    hostname VARCHAR(256) UNIQUE,
    ip INET,
    os VARCHAR(128),
    agent_id VARCHAR(64),
    tags TEXT[],
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_agent_id ON assets(agent_id);

-- =====================================================
-- 3. 漏洞表
-- =====================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT REFERENCES assets(id) ON DELETE CASCADE,
    cve VARCHAR(32),
    severity VARCHAR(16),
    scanner VARCHAR(32),
    title VARCHAR(256),
    description TEXT,
    remediation TEXT,
    status VARCHAR(16) DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);

-- =====================================================
-- 4. 情报库
-- =====================================================
CREATE TABLE IF NOT EXISTS ti_domains (
    domain VARCHAR(256) PRIMARY KEY,
    category VARCHAR(64),
    source VARCHAR(32),
    tags TEXT[],
    confidence FLOAT,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ti_ips (
    ip INET PRIMARY KEY,
    category VARCHAR(64),
    source VARCHAR(32),
    tags TEXT[],
    confidence FLOAT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_tags (
    id SERIAL PRIMARY KEY,
    tag VARCHAR(64) UNIQUE,
    category VARCHAR(64),
    description TEXT,
    auto_block BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 5. Agent 表
-- =====================================================
CREATE TABLE IF NOT EXISTS agents (
    id BIGSERIAL PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL,
    agent_key VARCHAR(64),
    hostname VARCHAR(256),
    ip INET,
    os VARCHAR(128),
    agent_version VARCHAR(32),
    status VARCHAR(16) DEFAULT 'offline',
    traffic_enabled BOOLEAN DEFAULT false,
    hids_enabled BOOLEAN DEFAULT false,
    rasp_enabled BOOLEAN DEFAULT false,
    last_heartbeat TIMESTAMPTZ,
    config JSONB,
    tags TEXT[],
    enrolled_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_uuid ON agents(uuid);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id BIGSERIAL PRIMARY KEY,
    agent_uuid TEXT REFERENCES agents(uuid) ON DELETE CASCADE,
    task_type VARCHAR(32),
    task_params JSONB,
    status VARCHAR(16) DEFAULT 'pending',
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tasks_agent ON agent_tasks(agent_uuid);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON agent_tasks(status);

-- =====================================================
-- 6. 报告表
-- =====================================================
CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    report_type VARCHAR(32),
    title VARCHAR(256),
    content JSONB,
    summary TEXT,
    stats JSONB,
    webhook_urls TEXT[],
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 7. 规则表
-- =====================================================
CREATE TABLE IF NOT EXISTS rules (
    id BIGSERIAL PRIMARY KEY,
    rule_type VARCHAR(32) NOT NULL,
    name VARCHAR(128),
    content TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- =====================================================
-- 8. 配置表
-- =====================================================
CREATE TABLE IF NOT EXISTS configs (
    id SERIAL PRIMARY KEY,
    key VARCHAR(128) UNIQUE NOT NULL,
    value JSONB,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 9. 系统日志表
-- =====================================================
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGSERIAL PRIMARY KEY,
    level VARCHAR(16),
    source VARCHAR(64),
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_syslogs_level ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_syslogs_created ON system_logs(created_at DESC);
