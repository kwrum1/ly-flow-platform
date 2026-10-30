"""文件操作函数 Hook 模块"""
import sys
import functools
import logging
from typing import Any, Callable

from ..config import RASPConfig
from ..detector.file_access import detect_sensitive_file


logger = logging.getLogger(__name__)

# 原始函数存储
_original_functions = {}


def _report_detection(event_type: str, result: dict, func_name: str, args: Any, enforce: bool = True) -> None:
    from ..blocking import handle_detection
    handle_detection(event_type, result, func_name, args, enforce=enforce)


def _patch_builtins_open() -> None:
    """Patch built-in open function"""
    import builtins

    _original_functions['builtin_open'] = builtins.open

    def patched_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
        result = detect_sensitive_file(str(file))
        if result:
            _report_detection('sensitive_file_access', result, 'open', file)
        return _original_functions['builtin_open'](
            file, mode, buffering, encoding, errors, newline, closefd, opener
        )

    builtins.open = patched_open


def _patch_os_open() -> None:
    """Patch os.open"""
    import os

    _original_functions['os_open'] = os.open

    def patched_open(path, flags, mode=0o777):
        result = detect_sensitive_file(str(path))
        if result:
            _report_detection('sensitive_file_access', result, 'os.open', path)
        return _original_functions['os_open'](path, flags, mode)

    os.open = patched_open


def _patch_os_path() -> None:
    """Patch os.path functions"""
    import os.path

    _original_functions['os_path_exists'] = os.path.exists
    _original_functions['os_path_isfile'] = os.path.isfile
    _original_functions['os_path_isdir'] = os.path.isdir

    def patched_exists(path):
        result = detect_sensitive_file(str(path))
        if result:
            _report_detection('sensitive_file_access', result, 'os.path.exists', path, enforce=False)
        return _original_functions['os_path_exists'](path)

    def patched_isfile(path):
        result = detect_sensitive_file(str(path))
        if result:
            _report_detection('sensitive_file_access', result, 'os.path.isfile', path, enforce=False)
        return _original_functions['os_path_isfile'](path)

    def patched_isdir(path):
        result = detect_sensitive_file(str(path))
        if result:
            _report_detection('sensitive_file_access', result, 'os.path.isdir', path, enforce=False)
        return _original_functions['os_path_isdir'](path)

    os.path.exists = patched_exists
    os.path.isfile = patched_isfile
    os.path.isdir = patched_isdir


def _patch_pathlib() -> None:
    """Patch pathlib.Path methods"""
    try:
        from pathlib import Path

        # 保存原始方法
        original_read = Path.read_text
        original_read_bytes = Path.read_bytes
        original_open = Path.open

        def patched_read_text(self, encoding=None, errors=None):
            result = detect_sensitive_file(str(self))
            if result:
                _report_detection('sensitive_file_access', result, 'Path.read_text', str(self))
            return original_read(self, encoding, errors)

        def patched_read_bytes(self):
            result = detect_sensitive_file(str(self))
            if result:
                _report_detection('sensitive_file_access', result, 'Path.read_bytes', str(self))
            return original_read_bytes(self)

        def patched_path_open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
            result = detect_sensitive_file(str(self))
            if result:
                _report_detection('sensitive_file_access', result, 'Path.open', str(self))
            return original_open(self, mode, buffering, encoding, errors, newline)

        Path.read_text = patched_read_text
        Path.read_bytes = patched_read_bytes
        Path.open = patched_path_open

        _original_functions['pathlib_read'] = original_read
        _original_functions['pathlib_read_bytes'] = original_read_bytes
        _original_functions['pathlib_open'] = original_open

    except ImportError:
        logger.debug("pathlib not available")


def _patch_io_open() -> None:
    """Patch io.open (different from builtins.open on some platforms)"""
    try:
        import io

        if hasattr(io, 'open'):
            _original_functions['io_open'] = io.open

            def patched_io_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
                result = detect_sensitive_file(str(file))
                if result:
                    _report_detection('sensitive_file_access', result, 'io.open', file)
                return _original_functions['io_open'](
                    file, mode, buffering, encoding, errors, newline
                )

            io.open = patched_io_open

    except ImportError:
        logger.debug("io module not available")


def patch() -> None:
    """应用文件操作相关 Hook"""
    try:
        _patch_builtins_open()
        logger.info("builtins.open hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch builtins.open: {e}")

    try:
        _patch_os_open()
        logger.info("os.open hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch os.open: {e}")

    try:
        _patch_os_path()
        logger.info("os.path hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch os.path: {e}")

    try:
        _patch_pathlib()
        logger.info("pathlib hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch pathlib: {e}")

    try:
        _patch_io_open()
        logger.info("io.open hooks applied")
    except Exception as e:
        logger.debug(f"Failed to patch io.open: {e}")


def unpatch() -> None:
    """卸载文件操作相关 Hook"""
    # 恢复 builtins
    try:
        import builtins
        if 'builtin_open' in _original_functions:
            builtins.open = _original_functions['builtin_open']
    except Exception:
        pass

    # 恢复 os
    try:
        import os
        if 'os_open' in _original_functions:
            os.open = _original_functions['os_open']
        if 'os_path_exists' in _original_functions:
            os.path.exists = _original_functions['os_path_exists']
        if 'os_path_isfile' in _original_functions:
            os.path.isfile = _original_functions['os_path_isfile']
        if 'os_path_isdir' in _original_functions:
            os.path.isdir = _original_functions['os_path_isdir']
    except Exception:
        pass

    # 恢复 pathlib
    try:
        from pathlib import Path
        if 'pathlib_read' in _original_functions:
            Path.read_text = _original_functions['pathlib_read']
        if 'pathlib_read_bytes' in _original_functions:
            Path.read_bytes = _original_functions['pathlib_read_bytes']
        if 'pathlib_open' in _original_functions:
            Path.open = _original_functions['pathlib_open']
    except Exception:
        pass

    # 恢复 io
    try:
        import io
        if 'io_open' in _original_functions:
            io.open = _original_functions['io_open']
    except Exception:
        pass

    _original_functions.clear()
    logger.info("File hooks unloaded")