"""RASP 全局追踪器模块"""
import sys
import os
from typing import Any, Callable, Optional, Dict

from .config import RASPConfig, get_config
from .detector import sql_injection, command_injection, file_access, deserialize
from .reporter import Reporter, get_reporter


# 追踪器函数
def rasp_trace(frame, event: str, arg: Any) -> Optional[Callable]:
    """
    全局追踪器函数

    Args:
        frame: 当前栈帧
        event: 事件类型 ('call', 'return', 'exception')
        arg: 事件相关参数

    Returns:
        追踪器函数（用于持续追踪）
    """
    config = get_config()
    if config is None:
        return rasp_trace

    try:
        if event == 'call':
            _handle_call(frame, config)
        elif event == 'return':
            _handle_return(frame, arg, config)
    except Exception:
        # 追踪器内部异常不应中断程序
        pass

    return rasp_trace


def _handle_call(frame, config: RASPConfig) -> None:
    """处理函数调用事件"""
    code = frame.f_code
    filename = code.co_filename
    func_name = code.co_name
    lineno = frame.f_lineno

    # 获取调用者信息
    caller_frame = frame.f_back
    caller_info = ""
    if caller_frame:
        caller_info = f"{caller_frame.f_code.co_filename}:{caller_frame.f_lineno}"

    # 构建上下文信息
    context = {
        'filename': filename,
        'function': func_name,
        'lineno': lineno,
        'caller': caller_info,
        'globals': {k: v for k, v in frame.f_globals.items()
                   if not k.startswith('_') and not callable(v) and not isinstance(v, type)},
    }

    # 检测 SQL 注入
    if config.sql_enabled:
        _check_sql(frame, context, config)

    # 检测命令注入
    if config.command_enabled:
        _check_command(frame, context, config)

    # 检测文件操作
    if config.file_enabled:
        _check_file(frame, context, config)

    # 检测反序列化
    if config.deserialize_enabled:
        _check_deserialize(frame, context, config)


def _handle_return(frame, arg, config: RASPConfig) -> None:
    """处理函数返回事件"""
    # 可以在这里添加返回值的检查逻辑
    pass


def _check_sql(frame, context: Dict, config: RASPConfig) -> None:
    """检查 SQL 注入"""
    code = frame.f_code

    # 检查是否调用了 SQL 相关方法
    # sqlite3, psycopg2, mysql.connector, pymongo 等
    try:
        local_vars = frame.f_locals

        # 检查常见 SQL 参数名
        for var_name, var_value in local_vars.items():
            if var_value is None:
                continue

            # 检查 SQL 相关的变量
            if any(name in var_name.lower() for name in ['sql', 'query', 'stmt']):
                if isinstance(var_value, str):
                    result = sql_injection.detect_sql_injection(var_value, config)
                    if result:
                        context.update(result)
                        _report_event(context, 'sql_injection')
    except Exception:
        pass


def _check_command(frame, context: Dict, config: RASPConfig) -> None:
    """检查命令注入"""
    try:
        local_vars = frame.f_locals

        # 检查常见命令参数名
        for var_name, var_value in local_vars.items():
            if var_value is None:
                continue

            if any(name in var_name.lower() for name in ['cmd', 'command', 'shell', 'exec']):
                if isinstance(var_value, (str, bytes)):
                    result = command_injection.detect_command_injection(
                        str(var_value), config
                    )
                    if result:
                        context.update(result)
                        _report_event(context, 'command_injection')
    except Exception:
        pass


def _check_file(frame, context: Dict, config: RASPConfig) -> None:
    """检查敏感文件访问"""
    try:
        local_vars = frame.f_locals

        for var_name, var_value in local_vars.items():
            if var_value is None:
                continue

            if any(name in var_name.lower() for name in ['path', 'file', 'filename']):
                if isinstance(var_value, (str, bytes)):
                    result = file_access.detect_sensitive_file(
                        str(var_value), config
                    )
                    if result:
                        context.update(result)
                        _report_event(context, 'sensitive_file_access')
    except Exception:
        pass


def _check_deserialize(frame, context: Dict, config: RASPConfig) -> None:
    """检查反序列化"""
    try:
        local_vars = frame.f_locals

        for var_name, var_value in local_vars.items():
            if var_value is None:
                continue

            if any(name in var_name.lower() for name in ['data', 'payload', 'obj']):
                if isinstance(var_value, bytes):
                    result = deserialize.detect_pickle_injection(var_value, config)
                    if result:
                        context.update(result)
                        _report_event(context, 'deserialize_injection')
                elif isinstance(var_value, (str, dict)):
                    result = deserialize.detect_yaml_injection(var_value, config)
                    if result:
                        context.update(result)
                        _report_event(context, 'deserialize_injection')
    except Exception:
        pass


def _report_event(context: Dict, event_type: str) -> None:
    """上报安全事件"""
    reporter = get_reporter()
    if reporter:
        event = {
            'type': event_type,
            'context': context,
        }
        reporter.report(event)