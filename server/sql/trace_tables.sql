-- ly-flow-platform 行为溯源模块数据库表
-- 支持会话持久化、智能清理

-- 行为会话表
CREATE TABLE IF NOT EXISTS trace_sessions (
    id VARCHAR(64) PRIMARY KEY,
    host_id VARCHAR(64) NOT NULL,
    sess_user VARCHAR(128),
    src_ip VARCHAR(45),
    dst_ips JSONB DEFAULT '[]',
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    event_count INT DEFAULT 0,
    risk_score INT DEFAULT 0,
    status VARCHAR(16) DEFAULT 'active',
    attack_type VARCHAR(64),
    mitre_tactic VARCHAR(32),
    mitre_technique VARCHAR(32),
    tags TEXT[],
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_trace_sessions_host_id ON trace_sessions(host_id);
CREATE INDEX idx_trace_sessions_start_time ON trace_sessions(start_time);
CREATE INDEX idx_trace_sessions_end_time ON trace_sessions(end_time);
CREATE INDEX idx_trace_sessions_status ON trace_sessions(status);
CREATE INDEX idx_trace_sessions_risk_score ON trace_sessions(risk_score);
CREATE INDEX idx_trace_sessions_src_ip ON trace_sessions(src_ip);

-- 行为事件表
CREATE TABLE IF NOT EXISTS trace_events (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES trace_sessions(id) ON DELETE CASCADE,
    host_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    order_num INT,
    event_type VARCHAR(64),
    action VARCHAR(64),
    subject VARCHAR(255),
    object TEXT,
    result VARCHAR(16),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    dst_port INT,
    evt_user VARCHAR(128),
    parent_process VARCHAR(255),
    command_line TEXT,
    risk_score INT DEFAULT 0,
    related_iocs JSONB DEFAULT '[]',
    alert_id VARCHAR(64),
    raw_data JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_trace_events_session_id ON trace_events(session_id);
CREATE INDEX idx_trace_events_host_id ON trace_events(host_id);
CREATE INDEX idx_trace_events_timestamp ON trace_events(timestamp);
CREATE INDEX idx_trace_events_event_type ON trace_events(event_type);
CREATE INDEX idx_trace_events_src_ip ON trace_events(src_ip);

-- 攻击时序表
CREATE TABLE IF NOT EXISTS trace_sequences (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES trace_sessions(id) ON DELETE CASCADE,
    attack_type VARCHAR(64),
    mitre_tactic VARCHAR(32),
    mitre_technique VARCHAR(32),
    risk_score INT DEFAULT 0,
    stages JSONB,
    evidence JSONB DEFAULT '[]',
    status VARCHAR(16) DEFAULT 'detected',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_trace_sequences_session_id ON trace_sequences(session_id);

-- IOC关联表
CREATE TABLE IF NOT EXISTS trace_ioc_relations (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES trace_sessions(id) ON DELETE CASCADE,
    event_id VARCHAR(64),
    ioc_type VARCHAR(32) NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_tags TEXT[],
    confidence DECIMAL(3,2) DEFAULT 0.5,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_trace_ioc_relations_session ON trace_ioc_relations(session_id);
CREATE INDEX idx_trace_ioc_relations_ioc_type ON trace_ioc_relations(ioc_type);
CREATE INDEX idx_trace_ioc_relations_ioc_value ON trace_ioc_relations(ioc_value);

-- 存储统计表
CREATE TABLE IF NOT EXISTS trace_storage_stats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    total_sessions BIGINT DEFAULT 0,
    total_events BIGINT DEFAULT 0,
    storage_bytes BIGINT DEFAULT 0,
    oldest_session TIMESTAMP,
    cleanup_count INT DEFAULT 0,
    cleanup_bytes BIGINT DEFAULT 0
);

CREATE INDEX idx_trace_storage_stats_timestamp ON trace_storage_stats(timestamp);

-- 清理配置表
CREATE TABLE IF NOT EXISTS trace_cleanup_config (
    id SERIAL PRIMARY KEY,
    retention_days INT DEFAULT 7,
    max_retention_days INT DEFAULT 180,
    cleanup_threshold DECIMAL(5,2) DEFAULT 70.0,
    high_risk_session_hours INT DEFAULT 24,
    high_risk_min_score INT DEFAULT 70,
    enabled BOOLEAN DEFAULT TRUE,
    last_cleanup TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 初始化清理配置
INSERT INTO trace_cleanup_config (retention_days, max_retention_days, cleanup_threshold, high_risk_session_hours)
VALUES (7, 180, 70.0, 24) ON CONFLICT DO NOTHING;
