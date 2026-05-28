-- ly-flow-platform 资产模块数据库表
-- 基于 Elkeid 资产管理风格

-- 主机分组表
CREATE TABLE IF NOT EXISTS host_groups (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    parent_id VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 主机表 (资产核心表)
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

    -- 状态信息
    status VARCHAR(16) DEFAULT 'offline',
    risk_level VARCHAR(16) DEFAULT 'low',
    last_heartbeat TIMESTAMP,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),

    -- 硬件指纹
    cpu VARCHAR(255),
    memory_mb BIGINT,
    disk_gb BIGINT,
    cloud_instance_id VARCHAR(128),

    -- 组织信息
    tags TEXT[],
    group_id VARCHAR(64) REFERENCES host_groups(id),
    department VARCHAR(128),
    owner VARCHAR(128),
    importance VARCHAR(16) DEFAULT 'medium',

    -- 统计信息
    alert_count INT DEFAULT 0,
    vuln_count INT DEFAULT 0,
    rasp_blocked INT DEFAULT 0,

    -- 元数据
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_hosts_status ON hosts(status);
CREATE INDEX idx_hosts_risk_level ON hosts(risk_level);
CREATE INDEX idx_hosts_os ON hosts(os);
CREATE INDEX idx_hosts_group_id ON hosts(group_id);
CREATE INDEX idx_hosts_last_heartbeat ON hosts(last_heartbeat);
CREATE INDEX idx_hosts_tags ON hosts USING GIN(tags);

-- 网络接口表
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

-- 开放端口表
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

CREATE INDEX idx_host_ports_host_id ON host_ports(host_id);
CREATE INDEX idx_host_ports_port ON host_ports(port);

-- 运行进程表
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

CREATE INDEX idx_host_processes_host_id ON host_processes(host_id);
CREATE INDEX idx_host_processes_name ON host_processes(name);

-- 软件表 (已安装软件)
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

CREATE INDEX idx_host_software_host_id ON host_software(host_id);
CREATE INDEX idx_host_software_name ON host_software(name);

-- 主机标签关联表
CREATE TABLE IF NOT EXISTS host_tags (
    host_id VARCHAR(64) REFERENCES hosts(id) ON DELETE CASCADE,
    tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (host_id, tag)
);

-- 资产变更历史表
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

CREATE INDEX idx_host_change_history_host_id ON host_change_history(host_id);
CREATE INDEX idx_host_change_history_changed_at ON host_change_history(changed_at);

-- 容器信息表 (简化版，不包含 K8s)
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

CREATE INDEX idx_host_containers_host_id ON host_containers(host_id);

-- 客户端性能监控表
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

CREATE INDEX idx_host_performance_host_id ON host_performance(host_id);
CREATE INDEX idx_host_performance_timestamp ON host_performance(timestamp);
