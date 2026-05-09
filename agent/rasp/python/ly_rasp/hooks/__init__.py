"""Hook 注册模块"""
import importlib
import sys
import logging
from typing import Optional

from ..config import RASPConfig
from ..reporter import set_reporter, get_reporter


logger = logging.getLogger(__name__)

# 已注册的 hooks
_registered_hooks = []


def apply_hooks(config: RASPConfig) -> None:
    """
    应用所有启用的 Hook

    Args:
        config: RASP 配置
    """
    from . import sql
    from . import command
    from . import file as file_hook

    if config.sql_enabled:
        sql.patch()
        _registered_hooks.append(('sql', sql.unpatch))
        logger.info("SQL hooks applied")

    if config.command_enabled:
        command.patch()
        _registered_hooks.append(('command', command.unpatch))
        logger.info("Command hooks applied")

    if config.file_enabled:
        file_hook.patch()
        _registered_hooks.append(('file', file_hook.unpatch))
        logger.info("File hooks applied")

    # 设置 reporter
    reporter = get_reporter()
    if reporter:
        set_reporter(reporter)


def unload_hooks() -> None:
    """卸载所有已注册的 Hook"""
    for name, unpatch_func in reversed(_registered_hooks):
        try:
            unpatch_func()
            logger.info(f"Unloaded {name} hooks")
        except Exception as e:
            logger.error(f"Failed to unload {name} hooks: {e}")

    _registered_hooks.clear()


__all__ = ['apply_hooks', 'unload_hooks']