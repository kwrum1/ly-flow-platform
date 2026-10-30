"""RASP 主入口模块"""
import sys
import os
import atexit
from typing import Optional

from .config import RASPConfig, get_config, load_config, set_config
from .tracer import rasp_trace
from .reporter import Reporter, set_reporter
from .request_hook import (
    RASPASGIMiddleware,
    RASPRequestBlocked,
    RASPWSGIMiddleware,
    inspect_http_request,
    request_hook_status,
)


_config: Optional[RASPConfig] = None
_reporter: Optional[Reporter] = None


def enable(server_addr: Optional[str] = None, agent_id: Optional[str] = None) -> None:
    """
    启用 RASP 防护

    Args:
        server_addr: Redis 服务器地址，格式为 host:port
        agent_id: 代理 ID，用于标识当前应用实例
    """
    global _config, _reporter

    if _reporter is not None:
        disable()

    # 加载配置，优先使用传入参数
    env_server = os.environ.get('RASP_SERVER')
    env_agent_id = os.environ.get('RASP_AGENT_ID')

    if server_addr is None:
        server_addr = env_server or "localhost:6379"
    if agent_id is None:
        agent_id = env_agent_id or f"python-{os.getpid()}"

    _config = load_config(
        server_addr=server_addr,
        agent_id=agent_id,
    )

    # 初始化上报器
    _reporter = Reporter(_config)
    set_reporter(_reporter)
    _reporter.start()

    # 注册清理函数
    atexit.register(disable)

    # 启用追踪
    sys.settrace(rasp_trace)

    # 加载并应用 Hook
    from . import hooks
    hooks.apply_hooks(_config)


def disable() -> None:
    """禁用 RASP 防护"""
    global _reporter
    sys.settrace(None)

    if _reporter is not None:
        _reporter.shutdown()
        _reporter = None
    set_reporter(None)

    # 卸载 Hook
    from . import hooks
    hooks.unload_hooks()


def get_config() -> Optional[RASPConfig]:
    """获取当前配置"""
    return _config


def get_reporter() -> Optional[Reporter]:
    """获取当前上报器"""
    return _reporter
