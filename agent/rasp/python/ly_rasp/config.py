"""RASP 配置模块"""
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


_current_config: Optional["RASPConfig"] = None


@dataclass  # noqa: MUTABLE_OK # noqa: SLOTS_OK - rotated credentials mutate; supported runtimes lack dataclass slots.
class RASPConfig:
    """RASP 配置类"""
    server_addr: str = "localhost:6379"
    redis_username: str = ""
    redis_password: str = ""
    redis_legacy_password: str = ""
    bridge_url: str = "http://127.0.0.1:17891"
    bridge_token: str = ""
    policy_id: str = ""
    fallback_path: str = "/var/lib/lyflow/rasp/fallback.jsonl"
    config_refresh_seconds: float = 30.0
    agent_id: str = ""
    sql_enabled: bool = True
    command_enabled: bool = True
    file_enabled: bool = True
    deserialize_enabled: bool = True
    log_level: str = "INFO"
    stream: str = "alerts:rasp"
    language: str = "python"
    app: str = "python-app"
    mode: str = "monitor"
    policy_version: int = 0
    block_on_hit: bool = False
    expires_at: Optional[datetime] = None
    fail_behavior: str = "disable"
    max_events_per_second: int = 100
    queue_capacity: int = 128
    read_limit_bytes: int = 64 * 1024
    cpu_budget_ms: int = 50
    memory_budget_bytes: int = 1024 * 1024
    restart_budget: int = 3
    binary_path: str = ""
    binary_sha256: str = ""

    # SQL 注入检测配置
    sql_block_patterns: list = field(default_factory=lambda: [
        r"UNION\s+SELECT",
        r";\s*DROP\s+TABLE",
        r";\s*DROP\s+DATABASE",
        r"--\s*$",
        r"/\*.*\*/",
        r"OR\s+1\s*=\s*1",
        r"OR\s+'[^']*'\s*=\s*'[^']*'",
        r"AND\s+1\s*=\s*2",
        r"EXEC\s*\(",
        r"EXECUTE\s+",
        r"XP_",
        r"SLEEP\s*\(",
        r"BENCHMARK\s*\(",
    ])

    # 命令注入检测配置
    cmd_block_patterns: list = field(default_factory=lambda: [
        r";\s*rm\s",
        r";\s*rmdir",
        r"\|\s*cat\s",
        r"\|\s*grep\s",
        r"&\s*notepad",
        r"&\s*cmd",
        r"&\s*powershell",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"eval\s*\(",
        r"__import__",
    ])

    # 敏感文件路径配置
    sensitive_paths: list = field(default_factory=lambda: [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/proc/self/",
        "/proc/environ",
        "/root/.ssh/",
        "/root/.bashrc",
        "/root/.bash_history",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
    ])


def load_config(
    server_addr: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> RASPConfig:
    """
    加载 RASP 配置

    Args:
        server_addr: Redis 服务器地址
        agent_id: 代理 ID

    Returns:
        RASPConfig: 配置对象
    """
    env_server = os.environ.get('RASP_SERVER', 'localhost:6379')
    env_agent_id = os.environ.get('RASP_AGENT_ID', f'python-{os.getpid()}')

    config = RASPConfig(
        server_addr=server_addr or env_server,
        redis_username=os.environ.get('REDIS_ACL_USERNAME', ''),
        redis_password=os.environ.get('REDIS_ACL_PASSWORD', ''),
        redis_legacy_password=os.environ.get('REDIS_PASSWORD', ''),
        bridge_url=os.environ.get('LY_RASP_BRIDGE_URL', 'http://127.0.0.1:17891'),
        bridge_token=os.environ.get('LY_RASP_TOKEN', ''),
        policy_id=os.environ.get('RASP_POLICY_ID', ''),
        fallback_path=os.environ.get('LY_RASP_FALLBACK_PATH', '/var/lib/lyflow/rasp/fallback.jsonl'),
        config_refresh_seconds=float(os.environ.get('LY_RASP_CONFIG_REFRESH_SECONDS', '30')),
        agent_id=agent_id or env_agent_id,
        sql_enabled=os.environ.get('RASP_SQL_ENABLED', 'true').lower() == 'true',
        command_enabled=os.environ.get('RASP_COMMAND_ENABLED', 'true').lower() == 'true',
        file_enabled=os.environ.get('RASP_FILE_ENABLED', 'true').lower() == 'true',
        deserialize_enabled=os.environ.get('RASP_DESERIALIZE_ENABLED', 'true').lower() == 'true',
        log_level=os.environ.get('RASP_LOG_LEVEL', 'INFO'),
        stream=os.environ.get('RASP_STREAM', 'alerts:rasp'),
        language=os.environ.get('RASP_LANGUAGE', 'python'),
        app=os.environ.get('RASP_APP', 'python-app'),
        mode=normalize_mode(os.environ.get('RASP_MODE', 'monitor')),
        policy_version=int(os.environ.get('RASP_POLICY_VERSION', '0')),
        block_on_hit=os.environ.get('RASP_BLOCK_ON_HIT', 'false').lower() == 'true',
        queue_capacity=int(os.environ.get('LY_RASP_QUEUE_CAPACITY', '128')),
        read_limit_bytes=int(os.environ.get('LY_RASP_READ_LIMIT_BYTES', str(64 * 1024))),
        cpu_budget_ms=int(os.environ.get('LY_RASP_CPU_BUDGET_MS', '50')),
        memory_budget_bytes=int(os.environ.get('LY_RASP_MEMORY_BUDGET_BYTES', str(1024 * 1024))),
        restart_budget=int(os.environ.get('LY_RASP_RESTART_BUDGET', '3')),
        binary_path=os.environ.get('LY_RASP_BINARY_PATH', ''),
        binary_sha256=os.environ.get('LY_RASP_BINARY_SHA256', ''),
    )

    set_config(config)
    return config


def set_config(config: Optional[RASPConfig]) -> None:
    """设置当前 RASP 配置。"""
    global _current_config
    _current_config = config


def get_config() -> Optional[RASPConfig]:
    """获取当前 RASP 配置。"""
    return _current_config


def normalize_mode(mode: str) -> str:
    """Normalize RASP policy mode with safe fallback."""
    normalized = str(mode or 'monitor').lower()
    if normalized in {'monitor', 'off'}:
        return normalized
    return 'monitor'


def should_block(config: Optional[RASPConfig] = None) -> bool:
    """Return whether detections should block the protected operation."""
    return False


def effective_mode(config: RASPConfig, now: Optional[datetime] = None) -> str:
    current = now or datetime.now(timezone.utc)
    if config.expires_at is None or current < config.expires_at:
        return normalize_mode(config.mode)
    if config.fail_behavior == "monitor":
        return "monitor"
    return "off"
