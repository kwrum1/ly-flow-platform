"""命令执行函数 Hook 模块"""
import sys
import functools
import logging
from typing import Any, Callable

from ..config import RASPConfig
from ..detector.command_injection import detect_command_injection


logger = logging.getLogger(__name__)

# 原始函数存储
_original_functions = {}


def _report_detection(event_type: str, result: dict, func_name: str, args: Any) -> None:
    """上报检测结果"""
    result['hooked_function'] = func_name
    result['args_preview'] = str(args)[:200]
    logger.warning(f"Command injection detected in {func_name}: {result}")
    from ..reporter import get_reporter
    reporter = get_reporter()
    if reporter:
        reporter.report({'type': event_type, 'details': result})


def _patch_os_system() -> None:
    """Patch os.system"""
    import os

    _original_functions['os_system'] = os.system

    def patched_system(command):
        result = detect_command_injection(str(command))
        if result:
            _report_detection('command_injection', result, 'os.system', command)
        return _original_functions['os_system'](command)

    os.system = patched_system


def _patch_os_popen() -> None:
    """Patch os.popen"""
    import os

    _original_functions['os_popen'] = os.popen

    def patched_popen(command, mode='r', buffering=-1):
        result = detect_command_injection(str(command))
        if result:
            _report_detection('command_injection', result, 'os.popen', command)
        return _original_functions['os_popen'](command, mode, buffering)

    os.popen = patched_popen


def _patch_subprocess() -> None:
    """Patch subprocess module"""
    import subprocess

    _original_functions['subprocess_run'] = subprocess.run
    _original_functions['subprocess_Popen'] = subprocess.Popen
    _original_functions['subprocess_call'] = subprocess.call
    _original_functions['subprocess_check_call'] = subprocess.check_call
    _original_functions['subprocess_check_output'] = subprocess.check_output

    def patched_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get('args', [])
        if isinstance(cmd, (list, str)):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
            result = detect_command_injection(cmd_str)
            if result:
                _report_detection('command_injection', result, 'subprocess.run', args)
        return _original_functions['subprocess_run'](*args, **kwargs)

    def patched_popen(*args, **kwargs):
        cmd = args[0] if args else kwargs.get('args', [])
        if isinstance(cmd, (list, str)):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
            result = detect_command_injection(cmd_str)
            if result:
                _report_detection('command_injection', result, 'subprocess.Popen', args)
        return _original_functions['subprocess_Popen'](*args, **kwargs)

    def patched_call(*args, **kwargs):
        cmd = args[0] if args else kwargs.get('args', [])
        if isinstance(cmd, (list, str)):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
            result = detect_command_injection(cmd_str)
            if result:
                _report_detection('command_injection', result, 'subprocess.call', args)
        return _original_functions['subprocess_call'](*args, **kwargs)

    def patched_check_call(*args, **kwargs):
        cmd = args[0] if args else kwargs.get('args', [])
        if isinstance(cmd, (list, str)):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
            result = detect_command_injection(cmd_str)
            if result:
                _report_detection('command_injection', result, 'subprocess.check_call', args)
        return _original_functions['subprocess_check_call'](*args, **kwargs)

    def patched_check_output(*args, **kwargs):
        cmd = args[0] if args else kwargs.get('args', [])
        if isinstance(cmd, (list, str)):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
            result = detect_command_injection(cmd_str)
            if result:
                _report_detection('command_injection', result, 'subprocess.check_output', args)
        return _original_functions['subprocess_check_output'](*args, **kwargs)

    subprocess.run = patched_run
    subprocess.Popen = patched_popen
    subprocess.call = patched_call
    subprocess.check_call = patched_check_call
    subprocess.check_output = patched_check_output


def _patch_eval() -> None:
    """Patch built-in eval and exec"""
    import builtins

    _original_functions['builtin_eval'] = builtins.eval
    _original_functions['builtin_exec'] = builtins.exec

    def patched_eval(source, globals=None, locals=None):
        source_str = str(source)
        result = detect_command_injection(source_str)
        if result:
            result['is_dynamic_code'] = True
            _report_detection('command_injection', result, 'eval', source)
        return _original_functions['builtin_eval'](source, globals, locals)

    def patched_exec(source, globals=None, locals=None):
        source_str = str(source)
        result = detect_command_injection(source_str)
        if result:
            result['is_dynamic_code'] = True
            _report_detection('command_injection', result, 'exec', source)
        return _original_functions['builtin_exec'](source, globals, locals)

    builtins.eval = patched_eval
    builtins.exec = patched_exec


def _patch_builtins() -> None:
    """Patch built-in __import__"""
    import builtins

    _original_functions['builtin_import'] = builtins.__import__

    def patched_import(name, globals=None, locals=None, fromlist=(), level=0):
        # 检查危险模块导入
        dangerous_modules = ['os', 'subprocess', 'socket', 'pty', 'telnetlib', 'ssh']
        if any(d in name for d in dangerous_modules):
            logger.warning(f"Dynamic import of dangerous module: {name}")
        return _original_functions['builtin_import'](name, globals, locals, fromlist, level)

    builtins.__import__ = patched_import


def patch() -> None:
    """应用命令执行相关 Hook"""
    try:
        _patch_os_system()
        logger.info("os.system hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch os.system: {e}")

    try:
        _patch_os_popen()
        logger.info("os.popen hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch os.popen: {e}")

    try:
        _patch_subprocess()
        logger.info("subprocess hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch subprocess: {e}")

    try:
        _patch_eval()
        logger.info("eval/exec hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch eval/exec: {e}")

    try:
        _patch_builtins()
        logger.info("__import__ hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch __import__: {e}")


def unpatch() -> None:
    """卸载命令执行相关 Hook"""
    # 恢复 os 模块
    try:
        import os
        if 'os_system' in _original_functions:
            os.system = _original_functions['os_system']
        if 'os_popen' in _original_functions:
            os.popen = _original_functions['os_popen']
    except Exception:
        pass

    # 恢复 subprocess
    try:
        import subprocess
        if 'subprocess_run' in _original_functions:
            subprocess.run = _original_functions['subprocess_run']
        if 'subprocess_Popen' in _original_functions:
            subprocess.Popen = _original_functions['subprocess_Popen']
        if 'subprocess_call' in _original_functions:
            subprocess.call = _original_functions['subprocess_call']
        if 'subprocess_check_call' in _original_functions:
            subprocess.check_call = _original_functions['subprocess_check_call']
        if 'subprocess_check_output' in _original_functions:
            subprocess.check_output = _original_functions['subprocess_check_output']
    except Exception:
        pass

    # 恢复 builtins
    try:
        import builtins
        if 'builtin_eval' in _original_functions:
            builtins.eval = _original_functions['builtin_eval']
        if 'builtin_exec' in _original_functions:
            builtins.exec = _original_functions['builtin_exec']
        if 'builtin_import' in _original_functions:
            builtins.__import__ = _original_functions['builtin_import']
    except Exception:
        pass

    _original_functions.clear()
    logger.info("Command hooks unloaded")