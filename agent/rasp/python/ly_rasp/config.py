"""RASP 配置模块"""
import os
from dataclasses import dataclass, field
from typing import Optional


_current_config: Optional["RASPConfig"] = None


@dataclass
class RASPConfig:
    """RASP 配置类"""
    server_addr: str = "localhost:6379"
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
    block_on_hit: bool = False

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
        block_on_hit=os.environ.get('RASP_BLOCK_ON_HIT', 'false').lower() == 'true',
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
    if normalized in {'monitor', 'protect', 'off'}:
        return normalized
    return 'monitor'


def should_block(config: Optional[RASPConfig] = None) -> bool:
    """Return whether detections should block the protected operation."""
    active = config or get_config()
    return bool(active and active.mode == 'protect' and active.block_on_hit)
